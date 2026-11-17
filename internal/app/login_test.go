package app_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/susu-dot-dev/authsu/internal/app"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/session"
)

// finishStub is a well-formed login finish body that no credential answers.
const finishStub = `{"id":"a","rawId":"a","type":"public-key","response":{}}`

const (
	loginBeginPath  = "/api/login/begin"
	loginFinishPath = "/api/login/finish"
	sessionPath     = "/api/session"
	logoutPath      = "/api/logout"
)

// loginCredID is the passkey's credential id and loginHandle the account's user
// handle. They are functions, not variables, so nothing can change them.
func loginCredID() []byte { return []byte("credential-id-0123456789") }
func loginHandle() []byte { return []byte("user-handle-0123456789abcdef0123") }

// loginEnv is the deployment configuration login needs: the same as
// registration's, which the two share.
func loginEnv(name string) string { return registrationEnv(name) }

func TestSessionRoutesOnlyAcceptTheirMethod(t *testing.T) {
	t.Parallel()

	// Every route but the session read is a POST: they change something.
	// Reading the session is a GET, which changes nothing.
	routes := map[string]string{
		loginBeginPath: http.MethodPost, loginFinishPath: http.MethodPost,
		logoutPath:  http.MethodPost,
		sessionPath: http.MethodGet,
	}

	for path, allow := range routes {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
			if method == allow {
				continue
			}

			t.Run(method+" "+path, func(t *testing.T) {
				t.Parallel()

				rec := httptest.NewRecorder()
				req := newRequest(t, method, path, nil)
				app.NewHandler(app.Deps{}, app.Platform{}).ServeHTTP(rec, req)

				if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != allow {
					t.Errorf("status = %d, Allow = %q, want 405 and %s", rec.Code, rec.Header().Get("Allow"), allow)
				}
			})
		}
	}
}

// There is no refresh: a session lasts its lifetime and the user signs in again.
// This pins that the route is gone, so it cannot come back unnoticed.
func TestThereIsNoRefreshRoute(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), method, "/api/refresh", nil)
		app.NewHandler(app.Deps{}, app.Platform{}).ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("%s /api/refresh = %d, want 404", method, rec.Code)
		}
	}
}

// With no database (the host stub), the routes that need one must answer 503
// rather than panic on a nil pointer.
func TestSessionRoutesWithoutADatabaseAreUnavailable(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		method string
		path   string
		body   string
	}{
		"login finish": {method: http.MethodPost, path: loginFinishPath, body: finishStub},
		"session":      {method: http.MethodGet, path: sessionPath},
		"logout":       {method: http.MethodPost, path: logoutPath},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			req := newRequest(t, tt.method, tt.path, strings.NewReader(tt.body))
			app.NewHandler(app.Deps{}, app.Platform{Getenv: loginEnv}).ServeHTTP(rec, req)

			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want %d: %s", rec.Code, http.StatusServiceUnavailable, rec.Body)
			}
		})
	}
}

// begin needs no database at all, so it works on the host stub.
func TestLoginBeginNeedsNoDatabase(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := newRequest(t, http.MethodPost, loginBeginPath, nil)
	app.NewHandler(app.Deps{}, app.Platform{Getenv: loginEnv}).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("begin = %d %s", rec.Code, rec.Body)
	}

	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

// A request whose body is not the expected JSON never reaches the service.
func TestLoginFinishRejectsBadJSON(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	app.NewHandler(app.Deps{}, app.Platform{}).ServeHTTP(rec,
		newRequest(t, http.MethodPost, loginFinishPath, strings.NewReader(`nope`)))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// credentialDB answers the credential lookup with a stored passkey, and every
// other read with no row. It is the little a login needs from the database
// besides the atomic write.
type credentialDB struct{ row []driver.Value }

func (d credentialDB) Connect(context.Context) (driver.Conn, error) { return credentialConn(d), nil }
func (credentialDB) Driver() driver.Driver                          { return nil }

type credentialConn struct{ row []driver.Value }

func (c credentialConn) Prepare(string) (driver.Stmt, error) { return credentialStmt(c), nil }
func (credentialConn) Close() error                          { return nil }
func (credentialConn) Begin() (driver.Tx, error)             { return nil, errDB }

type credentialStmt struct{ row []driver.Value }

func (credentialStmt) Close() error                               { return nil }
func (credentialStmt) NumInput() int                              { return -1 }
func (credentialStmt) Exec([]driver.Value) (driver.Result, error) { return nil, errDB }

func (s credentialStmt) Query([]driver.Value) (driver.Rows, error) {
	return &credentialRows{row: s.row, done: false}, nil
}

type credentialRows struct {
	row  []driver.Value
	done bool
}

func (*credentialRows) Columns() []string {
	return []string{"id", "user_id", "public_key", "flags", "user_handle", "role"}
}
func (*credentialRows) Close() error { return nil }

func (r *credentialRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}

	r.done = true
	copy(dest, r.row)

	return nil
}

// passkey is a software passkey: its private key and the canonical COSE_Key
// registration would have stored for it.
type passkey struct {
	priv *ecdsa.PrivateKey
	cose []byte
}

func newPasskey(t *testing.T) passkey {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	encoder, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("encoder: %v", err)
	}

	cose, err := encoder.Marshal(map[int64]any{
		1: 2, 3: -7, -1: 1,
		-2: priv.X.FillBytes(make([]byte, 32)),
		-3: priv.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("cose: %v", err)
	}

	return passkey{priv: priv, cose: cose}
}

// loginHandler is NewHandler over a fake database holding pk, and the batches it
// was asked to write.
func loginHandler(pk passkey) (http.Handler, *[][]atomic.Statement) {
	var batches [][]atomic.Statement

	handler := app.NewHandler(app.Deps{}, app.Platform{
		DB: sql.OpenDB(credentialDB{row: []driver.Value{
			"00000000-0000-7000-8000-000000000001", "00000000-0000-7000-8000-000000000002",
			pk.cose, int64(0x05), loginHandle(), "admin",
		}}),
		Getenv: loginEnv,
		Batch: func(_ context.Context, statements ...atomic.Statement) error {
			batches = append(batches, statements)

			return nil
		},
	})

	return handler, &batches
}

// postTo POSTs body to path on handler.
func postTo(t *testing.T, handler http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(t, http.MethodPost, path, strings.NewReader(body)))

	return rec
}

// beginChallenge runs login begin and returns the challenge it issued.
func beginChallenge(t *testing.T, handler http.Handler) string {
	t.Helper()

	begin := postTo(t, handler, loginBeginPath, "")
	if begin.Code != http.StatusOK {
		t.Fatalf("begin = %d %s", begin.Code, begin.Body)
	}

	var options struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}

	err := json.Unmarshal(begin.Body.Bytes(), &options)
	if err != nil {
		t.Fatalf("parse begin: %v", err)
	}

	return options.PublicKey.Challenge
}

// TestLoginOnTheHost drives begin and finish through NewHandler with a fake
// database and batch, which exercises the wiring the unit tests of each package
// cannot: the real clock, entropy, the routes and the cookie. The real SQL is
// proven by the e2e tests.
func TestLoginOnTheHost(t *testing.T) {
	t.Parallel()

	pk := newPasskey(t)
	handler, batches := loginHandler(pk)

	challenge := beginChallenge(t, handler)

	finish := postTo(t, handler, loginFinishPath, assertionBody(t, pk.priv, challenge))
	if finish.Code != http.StatusOK {
		t.Fatalf("finish = %d %s", finish.Code, finish.Body)
	}

	cookies := finish.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != session.CookieName || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatalf("cookies = %v, want one HttpOnly Secure session cookie", cookies)
	}

	// The token is only in the cookie.
	if strings.Contains(finish.Body.String(), cookies[0].Value) {
		t.Error("the response body carries the session token")
	}

	if len(*batches) != 1 || len((*batches)[0]) != 2 {
		t.Fatalf("batches = %v, want one batch of two statements (flags, session)", *batches)
	}
}

// assertionBody builds the finish request a browser would send for challenge,
// signed with priv.
func assertionBody(t *testing.T, priv *ecdsa.PrivateKey, challenge string) string {
	t.Helper()

	client, err := json.Marshal(map[string]any{
		typeMember: "webauthn.get", "challenge": challenge, "origin": testOrigin,
	})
	if err != nil {
		t.Fatalf("client data: %v", err)
	}

	hash := sha256.Sum256([]byte(testRPID))

	authData := append([]byte(nil), hash[:]...)
	authData = append(authData, 0x01|0x04) // UP | UV
	authData = binary.BigEndian.AppendUint32(authData, 0)

	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte(nil), authData...), clientHash[:]...))

	signature, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	id := base64.RawURLEncoding.EncodeToString(loginCredID())

	body, err := json.Marshal(map[string]any{
		"id": id, "rawId": id, typeMember: "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(client),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"signature":         base64.RawURLEncoding.EncodeToString(signature),
			"userHandle":        base64.RawURLEncoding.EncodeToString(loginHandle()),
		},
	})
	if err != nil {
		t.Fatalf("body: %v", err)
	}

	return string(body)
}
