//go:build e2e

package e2e_test

// shards_test.go runs the suite on several Workers at once.
//
// The tests are slow because each one waits on HTTP round trips and seeding,
// not because they are heavy, and one Worker serves them one at a time (they
// share a database, see docs/TESTING.md). So the suite is cut into slices, and
// each slice runs on its own Worker, on its own port, over its own database in
// its own state directory. Slices share nothing but the read-only build/, so no
// test can see another slice's data and no test needs to know it is sliced.
//
// A slice is a process started with E2E_SHARD_INDEX=i and E2E_SHARD_TOTAL=n: it
// runs every n-th test (declaration order, starting at i), which spreads the
// slow files across slices without a timing table to keep up to date. CI starts
// one such process per job, on separate machines.
//
// Locally, the process `go test` started is the coordinator: it re-executes
// itself once per slice with those variables set and prefixes each slice's
// output with its number. It never starts a Worker itself.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// shardCount is how many slices a local run uses: $E2E_SHARDS when set (1 turns
// sharding off), else defaultShards.
func shardCount() int {
	if value := os.Getenv(shardsEnv); value != "" {
		n, err := strconv.Atoi(value)
		if err == nil && n >= 1 {
			return n
		}
	}

	return defaultShards
}

// sliceFromEnv reads E2E_SHARD_INDEX and E2E_SHARD_TOTAL. ok is false when
// neither is set (a plain run); both must be valid when either is.
func sliceFromEnv() (int, int, bool, error) {
	indexText, totalText := os.Getenv(shardIndexEnv), os.Getenv(shardTotalEnv)
	if indexText == "" && totalText == "" {
		return 0, 0, false, nil
	}

	index, indexErr := strconv.Atoi(indexText)
	total, totalErr := strconv.Atoi(totalText)

	if indexErr != nil || totalErr != nil || total < 1 || index < 0 || index >= total {
		return 0, 0, false, fmt.Errorf("%w: %s=%q, %s=%q", errBadSlice, shardIndexEnv, indexText, shardTotalEnv, totalText)
	}

	return index, total, true, nil
}

// selectSlice narrows this process to its slice, if it has one, by setting
// -test.run to exactly its tests. A plain run is the whole suite.
func selectSlice(ctx context.Context) error {
	index, total, ok, err := sliceFromEnv()
	if err != nil || !ok {
		return err
	}

	if !flag.Parsed() {
		flag.Parse()
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find the test binary: %w", err)
	}

	names, err := listTests(ctx, exe)
	if err != nil {
		return err
	}

	// A slice with nothing to run must not fall back to running everything.
	pattern := "^$"
	if mine := shardOf(names, index, total); len(mine) > 0 {
		pattern = "^(" + strings.Join(quoteAll(mine), "|") + ")$"
	}

	err = flag.Set("test.run", pattern)
	if err != nil {
		return fmt.Errorf("select slice: %w", err)
	}

	return nil
}

// coordinate runs the tests that this process was asked for on shardCount
// shards in parallel and returns the exit code `go test` should report.
func coordinate(ctx context.Context, root string) int {
	// TestMain runs before testing has parsed the command line, and the flags
	// below are read through the flag package.
	if !flag.Parsed() {
		flag.Parse()
	}

	exe, err := os.Executable()
	if err != nil {
		return fail("find the test binary: %v", err)
	}

	names, err := listTests(ctx, exe)
	if err != nil {
		return fail("%v", err)
	}

	// Every shard gets its own state directory under a base the caller may
	// name (E2E_STATE) or, by default, the repository's git-ignored one.
	base := os.Getenv(stateDirEnv)
	if base == "" {
		base = defaultState
	}

	// Relative to root, like the single-Worker path: wrangler is run from root.
	err = os.RemoveAll(filepath.Join(root, base))
	if err != nil {
		return fail("clear state: %v", err)
	}

	count := min(shardCount(), max(len(names), 1))
	failed := make([]bool, count)

	var (
		wg  sync.WaitGroup
		out sync.Mutex
	)

	for shard := range count {
		wg.Go(func() {
			if len(shardOf(names, shard, count)) == 0 {
				return
			}

			failed[shard] = !runShard(ctx, exe, shard, count, filepath.Join(base, "shard"+strconv.Itoa(shard)), &out)
		})
	}

	wg.Wait()

	for shard, bad := range failed {
		if bad {
			_, _ = fmt.Fprintf(os.Stderr, "e2e: shard %d failed\n", shard)

			return 1
		}
	}

	return 0
}

// shardOf returns the tests of one shard: every count-th test, starting at
// shard.
func shardOf(names []string, shard, count int) []string {
	var mine []string

	for i := shard; i < len(names); i += count {
		mine = append(mine, names[i])
	}

	return mine
}

// listTests asks the test binary for the top-level tests that the command
// line selects, so -test.run given to `go test` still narrows the run.
// -test.list takes the pattern as its own argument and ignores -test.run.
func listTests(ctx context.Context, exe string) ([]string, error) {
	pattern := flagValue("run")
	if pattern == "" {
		pattern = "."
	}

	args := []string{"-test.list=" + pattern}

	if skip := flagValue("skip"); skip != "" {
		args = append(args, "-test.skip="+skip)
	}

	// -test.list still runs TestMain; the marker keeps it from coordinating or
	// starting a Worker.
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Env = append(os.Environ(), listOnlyEnv+"="+listOnlyMarker)

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("list tests: %w", err)
	}

	var names []string

	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.HasPrefix(line, "Test") && !strings.ContainsAny(line, " \t") {
			names = append(names, line)
		}
	}

	return names, nil
}

// flagValue is the current value of a testing flag, or "" when it is not
// defined. Reading them through the flag package means the spelling `go test`
// used (-test.v, -test.v=true, -test.timeout 5m) does not matter.
func flagValue(name string) string {
	if f := flag.Lookup("test." + name); f != nil {
		return f.Value.String()
	}

	return ""
}

// passThrough are the flags every slice inherits. -test.run and -test.skip go
// too: the slice lists the tests they select and then keeps its own share.
func passThrough() []string {
	var kept []string

	for _, name := range []string{"v", "timeout", "count", "failfast", "shuffle", "run", "skip"} {
		if value := flagValue(name); value != "" && value != flagOff && value != "off" {
			kept = append(kept, "-test."+name+"="+value)
		}
	}

	return kept
}

// runShard runs one slice to the end and reports whether it passed. Its output
// is held until it ends and then written in one piece, so slices never
// interleave; a passing slice prints only its summary line unless -v is on.
func runShard(ctx context.Context, exe string, shard, count int, state string, out *sync.Mutex) bool {
	cmd := exec.CommandContext(ctx, exe, passThrough()...)
	cmd.Env = append(os.Environ(),
		shardIndexEnv+"="+strconv.Itoa(shard),
		shardTotalEnv+"="+strconv.Itoa(count),
		stateDirEnv+"="+state)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var buf bytes.Buffer

	cmd.Stdout, cmd.Stderr = &buf, &buf

	err := cmd.Run()

	out.Lock()
	defer out.Unlock()

	report(os.Stdout, shard, buf.Bytes(), err == nil)

	return err == nil
}

// report writes a shard's output with a prefix on every line. A passing shard
// is reduced to its last line (ok/PASS) unless -test.v is on.
func report(dst io.Writer, shard int, output []byte, passed bool) {
	verbose := flagValue("v") != "" && flagValue("v") != flagOff

	prefix := "[shard " + strconv.Itoa(shard) + "] "
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<26)

	var lines []string

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if passed && !verbose {
		lines = lines[max(len(lines)-1, 0):]
	}

	for _, line := range lines {
		_, _ = fmt.Fprintln(dst, prefix+line)
	}
}

// flagOff is how the flag package prints a boolean flag that is not set.
const flagOff = "false"

var errBadSlice = errors.New("bad E2E_SHARD_INDEX/E2E_SHARD_TOTAL")

var nameMeta = regexp.MustCompile(`[.+*?()|\[\]{}^$\\]`)

// quoteAll escapes each test name for use inside a -test.run alternation. Test
// names are Go identifiers today, so this is a guard, not a need.
func quoteAll(names []string) []string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = nameMeta.ReplaceAllString(name, `\$0`)
	}

	return quoted
}
