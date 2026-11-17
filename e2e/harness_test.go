//go:build e2e

// Package e2e drives the real Worker: the TinyGo-compiled wasm running in
// workerd under `wrangler dev`, with a simulated D1 database.
//
// Unit tests cover logic on the host. These tests exist for what the host
// cannot see: TinyGo's net/http differences, the D1 driver, and the wrangler
// wiring itself.
//
// Run them with `make test-e2e`, which builds the Worker first. This
// harness only runs what was built: wrangler.e2e.jsonc has no build command, so
// wrangler never rebuilds it.
package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const (
	readyTimeout  = 3 * time.Minute
	readyInterval = 500 * time.Millisecond
	dialTimeout   = time.Second
	stateDirEnv   = "E2E_STATE"
	defaultState  = ".wrangler/e2e-state"

	// wranglerConfig is wrangler.jsonc without its build command, so wrangler
	// serves the build/ that make produced rather than running TinyGo again.
	wranglerConfig = "wrangler.e2e.jsonc"

	// firstRunSecret is the FIRST_RUN_SECRET the Worker under test is started
	// with. It is a fixed, throwaway value (43 characters, like a generated
	// one) so tests can compute what the Worker should have stored for it.
	firstRunSecret = "e2e-first-run-secret-0123456789ABCDEFGHIJKL"

	// authHMACSecret is the AUTH_HMAC_SECRET the Worker under test is started
	// with: fixed and throwaway, 43 characters like a generated one.
	authHMACSecret = "e2e-auth-hmac-secret-0123456789ABCDEFGHIJKLMN"

	// rpID is the relying party ID: the host of the UI origin, which the Worker
	// derives from UI_ORIGIN.
	rpID = "localhost"

	// uiPort is the port of the UI origin. No UI runs there; the origin is only
	// ever a string in clientDataJSON and an Origin header. It differs from the
	// Worker's own port, as it does in production (susu.dev and auth.susu.dev),
	// so the tests exercise a cross-origin UI.
	uiPort = "3000"

	// envFileName is written into the state directory and handed to wrangler
	// with --env-file. Nothing in the repository root is read or written, so a
	// developer's own .dev.vars is never used by, or clobbered by, a test run.
	envFileName = "e2e.env"

	envFilePerm = 0o600
)

var errNotReady = errors.New("worker not ready")

// worker is the running Worker under test.
type worker struct {
	baseURL string
	// origin is the UI origin: the relying party origin the Worker accepts
	// ceremonies from, and the one origin it allows cross-origin.
	origin string
	// apiOrigin is the origin the Worker is served from: its session issuer.
	apiOrigin string

	// root is the repository root and state the Worker's local D1 state
	// directory (relative to root), so tests can inspect the database.
	root  string
	state string
}

// target is set by TestMain before any test runs.
var target worker //nolint:gochecknoglobals // process-wide fixture shared by all e2e tests

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	root, err := filepath.Abs("..")
	if err != nil {
		return fail("resolve repo root: %v", err)
	}

	state := os.Getenv(stateDirEnv)
	if state == "" {
		state = defaultState
	}

	// A fresh database for every run, so tests never depend on leftovers.
	err = os.RemoveAll(filepath.Join(root, state))
	if err != nil {
		return fail("clear state: %v", err)
	}

	out, err := command(ctx, root, "npx", "wrangler", "d1", "migrations", "apply", "DB",
		"--config", wranglerConfig, "--local", "--persist-to", state).CombinedOutput()
	if err != nil {
		return fail("apply migrations: %v\n%s", err, out)
	}

	return serve(ctx, root, state, m)
}

// writeEnvFile writes the secrets and variables the Worker under test is
// configured with to dir, in the dotenv format wrangler's --env-file reads, and
// returns its path. The API origin depends on the port the Worker listens on,
// so both origins are parameters.
func writeEnvFile(dir, apiOrigin, uiOrigin string) (string, error) {
	err := os.MkdirAll(dir, 0o700)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}

	path := filepath.Join(dir, envFileName)

	contents := "FIRST_RUN_SECRET=" + firstRunSecret + "\n" +
		"AUTH_HMAC_SECRET=" + authHMACSecret + "\n" +
		"API_ORIGIN=" + apiOrigin + "\n" +
		"UI_ORIGIN=" + uiOrigin + "\n"

	err = os.WriteFile(path, []byte(contents), envFilePerm)
	if err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}

	return path, nil
}

// serve starts wrangler, waits for the Worker, runs the tests, and always tears
// wrangler (and the workerd it spawns) down.
func serve(ctx context.Context, root, state string, m *testing.M) int {
	port, err := freePort(ctx)
	if err != nil {
		return fail("pick port: %v", err)
	}

	apiOrigin := "http://" + rpID + ":" + port
	uiOrigin := "http://" + rpID + ":" + uiPort

	envFile, err := writeEnvFile(filepath.Join(root, state), apiOrigin, uiOrigin)
	if err != nil {
		return fail("write env file: %v", err)
	}

	inspector, err := freePort(ctx)
	if err != nil {
		return fail("pick inspector port: %v", err)
	}

	cmd := command(ctx, root, "npx", "wrangler", "dev", "--config", wranglerConfig, "--local",
		"--port", port, "--inspector-port", inspector,
		"--persist-to", state, "--env-file", envFile, "--show-interactive-dev-session=false")

	var logs bytes.Buffer

	cmd.Stdout, cmd.Stderr = &logs, &logs
	// Own process group, so one signal stops wrangler and workerd.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err = cmd.Start()
	if err != nil {
		return fail("start wrangler: %v", err)
	}

	defer func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		_ = cmd.Wait()
	}()

	// Tests connect to 127.0.0.1 (wrangler binds IPv4, and "localhost" may
	// resolve to ::1 first). The origins are only ever strings (inside
	// clientDataJSON, in an Origin header, in an issuer), so they can use the
	// name "localhost".
	target = worker{
		baseURL: "http://127.0.0.1:" + port, origin: uiOrigin, apiOrigin: apiOrigin, root: root, state: state,
	}

	err = waitReady(ctx, target.baseURL+"/healthz")
	if err != nil {
		return fail("%v\n--- wrangler output ---\n%s", err, logs.String())
	}

	code := m.Run()
	if code != 0 {
		_, _ = fmt.Fprintf(os.Stderr, "--- wrangler output ---\n%s\n", logs.String())
	}

	return code
}

func command(ctx context.Context, dir, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir

	return cmd
}

// freePort asks the OS for an unused TCP port.
func freePort(ctx context.Context) (string, error) {
	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("listen: %w", err)
	}
	defer func() { _ = lis.Close() }()

	_, port, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		return "", fmt.Errorf("split address: %w", err)
	}

	return port, nil
}

// waitReady polls url until the Worker answers or the timeout passes.
func waitReady(ctx context.Context, url string) error {
	deadline := time.Now().Add(readyTimeout)

	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("build readiness request: %w", err)
		}

		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()

			return nil
		}

		time.Sleep(readyInterval)
	}

	return fmt.Errorf("%w after %s", errNotReady, readyTimeout)
}

func fail(format string, args ...any) int {
	_, _ = fmt.Fprintf(os.Stderr, "e2e: "+format+"\n", args...)

	return 1
}
