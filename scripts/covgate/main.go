// Command covgate enforces the 100% statement coverage gate described in
// docs/TESTING.md ("Coverage").
//
// It reads a Go coverage profile and ignores:
//
//   - files under the excluded directories (default: cmd/worker, wasm-only glue
//     that only e2e can exercise, and scripts, dev tooling that is not
//     production code), and
//
//   - statements annotated with a comment of the form
//
//     // coverage:ignore: <reason>
//
//     placed on the line directly above the statement (or declaration). The
//     whole statement, including any nested block, is ignored. A marker with no
//     reason, or one that is not directly followed by a statement, is an error.
//
// Every honoured ignore is printed so it is visible in CI output and review.
//
// Usage: covgate [-profile coverage.out] [-module path] [-exclude dir,dir]
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	marker     = "coverage:ignore:"
	percentMax = 100.0
)

var (
	errBelowGate    = errors.New("coverage below 100%")
	errNoModule     = errors.New("no module directive")
	errBadProfile   = errors.New("malformed profile line")
	errNoReason     = errors.New("coverage:ignore requires a reason")
	errNoStatement  = errors.New("coverage:ignore is not directly followed by a statement")
	errFlagsInvalid = errors.New("invalid flags")
)

// block is one line of a coverage profile.
type block struct {
	file               string // path relative to the module root
	startLine, endLine int
	stmts, count       int
}

// ignore is a reviewed exclusion.
type ignore struct {
	file               string
	startLine, endLine int
	reason             string
}

// config is the parsed command line.
type config struct {
	profile  string
	module   string
	excluded []string
}

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err == nil {
		err = run(cfg, os.Stdout)
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "covgate:", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) (config, error) {
	fs := flag.NewFlagSet("covgate", flag.ContinueOnError)
	profile := fs.String("profile", "coverage.out", "coverage profile to check")
	module := fs.String("module", "", "module path stripped from profile file names (default: read go.mod)")
	exclude := fs.String("exclude", "cmd/worker,scripts", "comma-separated directories excluded from the gate")
	err := fs.Parse(args)
	if err != nil {
		return config{}, fmt.Errorf("%w: %w", errFlagsInvalid, err)
	}

	return config{profile: *profile, module: *module, excluded: strings.Split(*exclude, ",")}, nil
}

func run(cfg config, out io.Writer) error {
	module := cfg.module
	if module == "" {
		var err error
		module, err = modulePath("go.mod")
		if err != nil {
			return err
		}
	}

	blocks, err := readProfile(cfg.profile, module)
	if err != nil {
		return err
	}
	ignores, err := collectIgnores(blocks)
	if err != nil {
		return err
	}

	w := &printer{w: out}
	w.ignores(ignores)
	total, covered, misses := tally(blocks, ignores, cfg.excluded)
	w.summary(total, covered, misses)
	if w.err != nil {
		return fmt.Errorf("write report: %w", w.err)
	}
	if len(misses) > 0 {
		return errBelowGate
	}

	return nil
}

// tally counts gated statements and returns the uncovered blocks, sorted.
func tally(blocks []block, ignores []ignore, excluded []string) (int, int, []block) {
	var total, covered int
	var misses []block
	for _, b := range blocks {
		if isExcluded(b.file, excluded) || isIgnored(b, ignores) {
			continue
		}
		total += b.stmts
		if b.count > 0 {
			covered += b.stmts
		} else {
			misses = append(misses, b)
		}
	}
	sort.Slice(misses, func(i, j int) bool {
		if misses[i].file != misses[j].file {
			return misses[i].file < misses[j].file
		}

		return misses[i].startLine < misses[j].startLine
	})

	return total, covered, misses
}

func modulePath(gomod string) (string, error) {
	f, err := os.Open(filepath.Clean(gomod))
	if err != nil {
		return "", fmt.Errorf("read module path: %w", err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "module "); ok {
			return strings.TrimSpace(rest), nil
		}
	}

	return "", fmt.Errorf("%s: %w", gomod, errNoModule)
}

// readProfile parses a coverprofile: "file:l.c,l.c stmts count" per line.
func readProfile(path, module string) ([]block, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("open profile: %w", err)
	}
	defer func() { _ = f.Close() }()

	var blocks []block
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "mode:") || line == "" {
			continue
		}
		b, err := parseBlock(line, module)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, b)
	}
	err = sc.Err()
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}

	return blocks, nil
}

func parseBlock(line, module string) (block, error) {
	file, rest, ok := strings.Cut(line, ":")
	if !ok {
		return block{}, fmt.Errorf("%w: %q", errBadProfile, line)
	}
	var sl, sc, el, ec, stmts, count int
	_, err := fmt.Sscanf(rest, "%d.%d,%d.%d %d %d", &sl, &sc, &el, &ec, &stmts, &count)
	if err != nil {
		return block{}, fmt.Errorf("%w: %q", errBadProfile, line)
	}

	return block{
		file:      strings.TrimPrefix(file, module+"/"),
		startLine: sl, endLine: el, stmts: stmts, count: count,
	}, nil
}

func isExcluded(file string, dirs []string) bool {
	for _, d := range dirs {
		d = strings.Trim(d, "/ ")
		if d != "" && strings.HasPrefix(file, d+"/") {
			return true
		}
	}

	return false
}

func isIgnored(b block, ignores []ignore) bool {
	for _, ig := range ignores {
		if ig.file == b.file && b.startLine >= ig.startLine && b.endLine <= ig.endLine {
			return true
		}
	}

	return false
}

// collectIgnores parses each profiled file once and resolves its markers.
func collectIgnores(blocks []block) ([]ignore, error) {
	seen := map[string]bool{}
	var all []ignore
	for _, b := range blocks {
		if seen[b.file] {
			continue
		}
		seen[b.file] = true
		igs, err := fileIgnores(b.file)
		if err != nil {
			return nil, err
		}
		all = append(all, igs...)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].file != all[j].file {
			return all[i].file < all[j].file
		}

		return all[i].startLine < all[j].startLine
	})

	return all, nil
}

func fileIgnores(path string) ([]ignore, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.FromSlash(path), nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	spans := statementSpans(fset, f)

	var igs []ignore
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
			rest, ok := strings.CutPrefix(text, marker)
			if !ok {
				continue
			}
			line := fset.Position(c.Pos()).Line
			reason := strings.TrimSpace(rest)
			if reason == "" {
				return nil, fmt.Errorf("%s:%d: %w", path, line, errNoReason)
			}
			// The statement must start on the line after the comment group.
			next := fset.Position(cg.End()).Line + 1
			end, ok := spans[next]
			if !ok {
				return nil, fmt.Errorf("%s:%d: %w", path, line, errNoStatement)
			}
			igs = append(igs, ignore{file: path, startLine: next, endLine: end, reason: reason})
		}
	}

	return igs, nil
}

// statementSpans maps the start line of each statement or declaration to the
// last line it covers.
func statementSpans(fset *token.FileSet, f *ast.File) map[int]int {
	spans := map[int]int{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n.(type) {
		case ast.Stmt, ast.Decl:
			start := fset.Position(n.Pos()).Line
			end := fset.Position(n.End()).Line
			spans[start] = max(spans[start], end)
		}

		return true
	})

	return spans
}

// printer writes the report and remembers the first write error.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) printf(format string, args ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format, args...)
}

func (p *printer) ignores(igs []ignore) {
	if len(igs) == 0 {
		p.printf("coverage:ignore: none\n")

		return
	}
	p.printf("coverage:ignore: %d ignored\n", len(igs))
	for _, ig := range igs {
		p.printf("  %s:%d-%d  %s\n", ig.file, ig.startLine, ig.endLine, ig.reason)
	}
}

func (p *printer) summary(total, covered int, misses []block) {
	pct := percentMax
	if total > 0 {
		pct = percentMax * float64(covered) / float64(total)
	}
	p.printf("coverage: %.1f%% (%d/%d statements)\n", pct, covered, total)
	for _, b := range misses {
		p.printf("  uncovered: %s:%d-%d\n", b.file, b.startLine, b.endLine)
	}
}
