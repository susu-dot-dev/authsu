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
	"regexp"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/susu-dot-dev/authsu/internal/app"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/firstrun"
	"github.com/susu-dot-dev/authsu/internal/registration"
	"github.com/susu-dot-dev/authsu/internal/webauthn"
)

const (
	testRPID   = "example.com"
	testOrigin = "https://example.com"
	testAPI    = "https://auth.example.com"
	testCode   = "an-invitation-code-0123456789ABCDEFGHIJKL"
	beginPath  = "/api/register/begin"
	typeMember = "type"
	finishPath = "/api/register/finish"
)

// registrationEnv is the deployment configuration registration needs.
func registrationEnv(name string) string {
	return map[string]string{
		registration.SecretHMAC:   "registration-secret-0123456789ABCDEFGHIJ",
		registration.VarAPIOrigin: testAPI,
		registration.VarUIOrigin:  testOrigin,
	}[name]
}

func registrationRoutes() []string { return []string{beginPath, finishPath} }

func TestRegistrationRoutesOnlyAcceptPost(t *testing.T) {
	t.Parallel()

	for _, path := range registrationRoutes() {
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			t.Run(method+" "+path, func(t *testing.T) {
				t.Parallel()

				rec := httptest.NewRecorder()
				req := newRequest(t, method, path, nil)
				app.NewHandler(app.Platform{}).ServeHTTP(rec, req)

				if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
					t.Errorf("status = %d, Allow = %q, want 405 and POST", rec.Code, rec.Header().Get("Allow"))
				}
			})
		}
	}
}

// With no database (the host stub), registration must answer 503 rather than
// panic on a nil pointer.
func TestRegistrationWithoutADatabaseIsUnavailable(t *testing.T) {
	t.Parallel()

	for _, path := range registrationRoutes() {
		rec := httptest.NewRecorder()
		body := strings.NewReader(`{"invitationCode":"c","name":"n"}`)
		app.NewHandler(app.Platform{Getenv: registrationEnv}).ServeHTTP(rec,
			newRequest(t, http.MethodPost, path, body))

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: status = %d, want %d", path, rec.Code, http.StatusServiceUnavailable)
		}
	}
}

// A request whose body is not the expected JSON never reaches the service.
func TestRegistrationRejectsBadJSON(t *testing.T) {
	t.Parallel()

	for _, path := range registrationRoutes() {
		rec := httptest.NewRecorder()
		app.NewHandler(app.Platform{}).ServeHTTP(rec,
			newRequest(t, http.MethodPost, path, strings.NewReader(`nope`)))

		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want %d", path, rec.Code, http.StatusBadRequest)
		}
	}
}

// The registration routes cap their bodies far below the default 1 MiB, because
// a legitimate request is a few KiB: a body over the cap is refused with 413
// before any JSON is parsed, and a body exactly at it is still read (and then
// fails as the malformed JSON it is, not as too large).
func TestRegistrationBodyCaps(t *testing.T) {
	t.Parallel()

	caps := map[string]int{
		beginPath:  registration.MaxBeginBody,
		finishPath: registration.MaxFinishBody,
	}

	for path, limit := range caps {
		for name, tt := range map[string]struct {
			size int
			want int
		}{
			"at the cap":     {size: limit, want: http.StatusBadRequest},
			"one over":       {size: limit + 1, want: http.StatusRequestEntityTooLarge},
			"far over":       {size: limit * 10, want: http.StatusRequestEntityTooLarge},
			"near the 1 MiB": {size: 1 << 20, want: http.StatusRequestEntityTooLarge},
			"over the 1 MiB": {size: 2 << 20, want: http.StatusRequestEntityTooLarge},
		} {
			t.Run(path+" "+name, func(t *testing.T) {
				t.Parallel()

				rec := httptest.NewRecorder()
				app.NewHandler(app.Platform{Getenv: registrationEnv}).ServeHTTP(rec,
					newRequest(t, http.MethodPost, path, strings.NewReader(strings.Repeat("a", tt.size))))

				if rec.Code != tt.want {
					t.Errorf("status = %d, want %d", rec.Code, tt.want)
				}
			})
		}
	}
}

// A finish request with more transports than allowed is refused at the route
// with the code that names the problem, and never reaches the database (the
// host stub has none, so reaching it would be a 503).
func TestRegistrationFinishRefusesTooManyTransports(t *testing.T) {
	t.Parallel()

	body := `{"invitationCode":"c","name":"n","credential":{"response":{"transports":[` +
		strings.Repeat(`"a",`, webauthn.MaxTransports) + `"a"]}}}`

	rec := httptest.NewRecorder()
	app.NewHandler(app.Platform{Getenv: registrationEnv}).ServeHTTP(rec,
		newRequest(t, http.MethodPost, finishPath, strings.NewReader(body)))

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "too_many_items") {
		t.Errorf("status = %d, body = %q, want 400 too_many_items", rec.Code, rec.Body.String())
	}
}

// registration repeats firstrun.InvitationType so it need not import that
// package; this pins the two together.
func TestRegistrationKnowsTheFirstRunInvitationType(t *testing.T) {
	t.Parallel()

	role, known := registration.RoleFor(firstrun.InvitationType)
	if !known || role != registration.RoleAdmin {
		t.Errorf("RoleFor(%q) = (%q, %v), want (%q, true)", firstrun.InvitationType, role, known, registration.RoleAdmin)
	}
}

// invitationDB is a database/sql driver that reports the first-run invitation
// as redeemable for any code, which is all a registration needs from the
// database besides the atomic write.
type invitationDB struct{}

func (invitationDB) Connect(context.Context) (driver.Conn, error) { return invitationConn{}, nil }
func (invitationDB) Driver() driver.Driver                        { return nil }

type invitationConn struct{}

func (invitationConn) Prepare(string) (driver.Stmt, error) { return invitationStmt{}, nil }
func (invitationConn) Close() error                        { return nil }
func (invitationConn) Begin() (driver.Tx, error)           { return nil, errDB }

type invitationStmt struct{}

func (invitationStmt) Close() error                               { return nil }
func (invitationStmt) NumInput() int                              { return -1 }
func (invitationStmt) Exec([]driver.Value) (driver.Result, error) { return nil, errDB }

func (invitationStmt) Query([]driver.Value) (driver.Rows, error) {
	return &invitationRows{done: false}, nil
}

type invitationRows struct{ done bool }

func (*invitationRows) Columns() []string { return []string{"type"} }
func (*invitationRows) Close() error      { return nil }

func (r *invitationRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}

	r.done = true
	dest[0] = firstrun.InvitationType

	return nil
}

// TestRegistrationOnTheHost drives begin and finish through NewHandler with a
// fake database and batch, which exercises the wiring the unit tests of each
// package cannot: the real clock, entropy and id source, and the routes. The
// real SQL is proven by the e2e tests.
func TestRegistrationOnTheHost(t *testing.T) {
	t.Parallel()

	var batches [][]atomic.Statement

	handler := app.NewHandler(app.Platform{
		DB:     sql.OpenDB(invitationDB{}),
		Getenv: registrationEnv,
		Batch: func(_ context.Context, statements ...atomic.Statement) ([]atomic.Result, error) {
			batches = append(batches, statements)

			return make([]atomic.Result, len(statements)), nil
		},
	})

	post := func(path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, newRequest(t, http.MethodPost, path, strings.NewReader(body)))

		return rec
	}

	begin := post(beginPath, `{"invitationCode":"`+testCode+`","name":"Alice"}`)
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

	finish := post(finishPath, registrationBody(t, options.PublicKey.Challenge))
	if finish.Code != http.StatusCreated {
		t.Fatalf("finish = %d %s", finish.Code, finish.Body)
	}

	if len(batches) != 1 || len(batches[0]) != 2 {
		t.Fatalf("batches = %v, want one batch of two statements", batches)
	}

	// The ids come from the wired UUIDv7 source.
	uuidv7 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	for _, statement := range batches[0] {
		if id, _ := statement.Args[0].(string); !uuidv7.MatchString(id) {
			t.Errorf("id = %q, want a lowercase UUIDv7", id)
		}
	}
}

// registrationBody builds the finish request a browser would send for
// challenge, with a fresh ES256 key and a "none" attestation.
func registrationBody(t *testing.T, challenge string) string {
	t.Helper()

	credID := []byte("credential-id-0123456789")
	id := base64.RawURLEncoding.EncodeToString(credID)

	clientData, err := json.Marshal(map[string]any{
		typeMember: "webauthn.create", "challenge": challenge, "origin": testOrigin,
	})
	if err != nil {
		t.Fatalf("client data: %v", err)
	}

	body, err := json.Marshal(map[string]any{
		"invitationCode": testCode,
		"name":           "Alice",
		"credential": map[string]any{
			"id": id, "rawId": id, typeMember: "public-key",
			"response": map[string]any{
				"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
				"attestationObject": base64.RawURLEncoding.EncodeToString(attestationObject(t, credID)),
			},
		},
	})
	if err != nil {
		t.Fatalf("body: %v", err)
	}

	return string(body)
}

// attestationObject is a "none" attestation for credID over a fresh ES256 key.
func attestationObject(t *testing.T, credID []byte) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	encoder, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("encoder: %v", err)
	}

	cose, err := encoder.Marshal(map[int64]any{
		1: 2, 3: -7, -1: 1,
		-2: key.X.FillBytes(make([]byte, 32)),
		-3: key.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("cose: %v", err)
	}

	hash := sha256.Sum256([]byte(testRPID))

	authData := make([]byte, 0, len(hash)+1+4+16+2+len(credID)+len(cose))
	authData = append(authData, hash[:]...)
	authData = append(authData, 0x01|0x04|0x40) // UP | UV | AT
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, make([]byte, 16)...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(min(len(credID), 1023)))
	authData = append(authData, credID...)
	authData = append(authData, cose...)

	object, err := encoder.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		t.Fatalf("attestation object: %v", err)
	}

	return object
}
