package agents

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/deploy"
	"github.com/susu-dot-dev/authsu/internal/session"
)

const createBody = `{"name":"assistant"}`

func (f *fixture) create(t *testing.T, body string) error {
	t.Helper()

	_, err := f.call(t, pathCollection, http.MethodPost, "", body)

	return err
}

func TestCreateWritesTheAgentAndItsKeyAsOneBatchAndReturnsTheKeyOnce(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	resp, err := fix.call(t, pathCollection, http.MethodPost, "", createBody)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.Status)
	}

	expires := testNow().Add(KeyLifetime).Unix()
	want := `{"agent":{"id":"` + testNewID + `","name":"assistant","scopes":"default:agent","status":"active",` +
		`"createdAt":` + itoa(testNow().Unix()) + `},"key":{"id":"` + testKeyID + `",` +
		`"token":"header.payload.signature","scope":"default:agent","expiresAt":` + itoa(expires) + `}}`

	if got := bodyOf(t, resp); got != want {
		t.Errorf("body = %s\nwant   %s", got, want)
	}

	if len(fix.batcher.batches) != 1 {
		t.Fatalf("ran %d batches, want 1: the agent and its key stand or fall together", len(fix.batcher.batches))
	}

	now := testNow().Unix()
	wantBatch := []atomic.Statement{
		{Query: insertAgentQuery, Args: []any{testNewID, testName, DefaultScopes, now, testUserID, int64(MaxAgentsPerUser)}},
		{Query: insertKeyQuery, Args: []any{testKeyID, testNewID, `{"keys":[]}`, expires, testNewID, DefaultScopes, now}},
	}

	if !reflect.DeepEqual(fix.batcher.batches[0], wantBatch) {
		t.Errorf("batch = %v, want %v", fix.batcher.batches[0], wantBatch)
	}

	// The response is built from what was written, never read back.
	if fix.reader.gets != 0 {
		t.Errorf("create read the row %d times, want 0", fix.reader.gets)
	}
}

// TestCreateMintsAKeyWhoseSubjectIsTheUserAndActorTheAgent: the central
// decision of docs/agents_design.md, written into the token.
func TestCreateMintsAKeyWhoseSubjectIsTheUserAndActorTheAgent(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	err := fix.create(t, createBody)
	if err != nil {
		t.Fatal(err)
	}

	if len(fix.minter.specs) != 1 {
		t.Fatalf("minted %d keys, want 1", len(fix.minter.specs))
	}

	want := session.Spec{
		Kind: session.KindAPIKey, Subject: testUserID, Expires: testNow().Add(KeyLifetime),
		Claims: map[string]any{"act": map[string]any{"sub": testNewID}, "scope": DefaultScopes},
	}

	if !reflect.DeepEqual(fix.minter.specs[0], want) {
		t.Errorf("spec = %+v, want %+v", fix.minter.specs[0], want)
	}

	api, parseErr := deploy.ParseOrigin(testOrigin)
	if parseErr != nil {
		t.Fatal(parseErr)
	}

	if fix.minter.issuer[0] != session.IssuerFor(api) {
		t.Errorf("issuer = %+v, want the deployment's", fix.minter.issuer[0])
	}
}

// TestTheOwnerIsTheSessionsUserNeverTheRequests: the body has no way to name an
// owner, and the write binds the authenticated user.
func TestTheOwnerIsTheSessionsUserNeverTheRequests(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	err := fix.create(t, `{"name":"a","userId":"`+otherUserID+`"}`)
	wantFailure(t, err, apierr.BadRequest, "unknown_field")

	if len(fix.batcher.batches) != 0 {
		t.Error("a request naming an owner wrote something")
	}
}

func TestCreateValidatesBeforeAuthenticating(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", MaxNameChars+1)

	tests := map[string]struct {
		body string
		code string
	}{
		"empty body":          {body: "", code: "empty_body"},
		"not json":            {body: badID, code: "invalid_json"},
		"unknown member":      {body: `{"name":"a","scopes":"x"}`, code: "unknown_field"},
		"wrong type":          {body: `{"name":1}`, code: "invalid_field_type"},
		"no name":             {body: `{}`, code: CodeInvalidName},
		"empty name":          {body: `{"name":""}`, code: CodeInvalidName},
		"blank name":          {body: `{"name":"  \t"}`, code: CodeInvalidName},
		"name too long":       {body: `{"name":"` + long + `"}`, code: CodeInvalidName},
		"nul in name":         {body: `{"name":"a\u0000b"}`, code: CodeInvalidName},
		"newline in name":     {body: `{"name":"a\nb"}`, code: CodeInvalidName},
		"tab in name":         {body: `{"name":"a\tb"}`, code: CodeInvalidName},
		"delete in name":      {body: `{"name":"a\u007fb"}`, code: CodeInvalidName},
		"c1 control in name":  {body: `{"name":"a\u0085b"}`, code: CodeInvalidName},
		"zero width space":    {body: `{"name":"a\u200bb"}`, code: CodeInvalidName},
		"bidi override":       {body: `{"name":"a\u202eb"}`, code: CodeInvalidName},
		"bidi isolate":        {body: `{"name":"a\u2066b"}`, code: CodeInvalidName},
		"byte order mark":     {body: `{"name":"\ufeffa"}`, code: CodeInvalidName},
		"soft hyphen":         {body: `{"name":"a\u00adb"}`, code: CodeInvalidName},
		"lone surrogate":      {body: `{"name":"a\ud800b"}`, code: "invalid_text"},
		"literal replacement": {body: `{"name":"a\ufffdb"}`, code: "invalid_text"},
		"no-break space only": {body: `{"name":"\u00a0"}`, code: CodeInvalidName},
		"trailing data":       {body: `{"name":"a"} {}`, code: "trailing_data"},
		"duplicate name key":  {body: `{"name":"a","name":"b"}`, code: "duplicate_field"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)

			err := fix.create(t, tt.body)
			wantFailure(t, err, apierr.BadRequest, tt.code)

			if fix.sessions.calls != 0 || len(fix.batcher.batches) != 0 || len(fix.minter.specs) != 0 {
				t.Error("an invalid request was authenticated, minted for or written")
			}
		})
	}
}

// TestNamesAreCountedInCharacters: the schema counts characters, not bytes.
func TestNamesAreCountedInCharacters(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	err := fix.create(t, `{"name":"`+strings.Repeat("é", MaxNameChars)+`"}`)
	if err != nil {
		t.Errorf("a name of exactly %d characters = %v, want it accepted", MaxNameChars, err)
	}
}

func TestCreateFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		batchErr error
		mintErr  error
		results  []atomic.Result
		kind     apierr.Kind
		code     string
	}{
		caseDBDown: {batchErr: errDB, kind: apierr.Unavailable, code: CodeCreateFailed},
		"user at the limit or revoked": {
			batchErr: atomic.ErrConflict, kind: apierr.Conflict, code: CodeLimit,
		},
		caseRejects: {batchErr: atomic.ErrRejected, kind: apierr.Internal, code: CodeCreateRejected},
		"key cannot be minted": {
			mintErr: errDB, kind: apierr.Internal, code: CodeKeyFailed,
		},
		"batch misreports": {
			results: []atomic.Result{{}}, kind: apierr.Internal, code: CodeCreateRejected,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			fix.batcher.err = tt.batchErr
			fix.minter.err = tt.mintErr
			fix.batcher.results = tt.results

			err := fix.create(t, createBody)
			wantFailure(t, err, tt.kind, tt.code)

			// A key that cannot be minted writes nothing.
			if tt.mintErr != nil && len(fix.batcher.batches) != 0 {
				t.Error("an agent was written for a key that could not be minted")
			}
		})
	}
}

// TestCreateFailsWithoutDeploymentConfig: the issuer is derived from the API
// origin, so a deployment without it cannot mint.
func TestCreateFailsWithoutDeploymentConfig(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	handler := fix.svc.Handlers(func(string) string { return "" }).Collection[http.MethodPost]

	_, err := handler(request(t, http.MethodPost, "", createBody)).Get()
	wantFailure(t, err, apierr.Unavailable, session.CodeNotConfigured)

	if len(fix.batcher.batches) != 0 {
		t.Error("wrote without a configured issuer")
	}
}

func TestKeyLifetimeIsFixed(t *testing.T) {
	t.Parallel()

	if KeyLifetime != 90*24*time.Hour {
		t.Errorf("KeyLifetime = %v", KeyLifetime)
	}
}
