package agents

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/atomic"
	"github.com/susu-dot-dev/authsu/internal/session"
)

// TestEveryWriteIsBoundToTheAuthenticatedUser: permission confusion. Whatever
// the request says, the owner bound into each statement is the session's user.
// An id of another user's agent is carried verbatim: it is the statement's own
// owner condition (pinned in the sql tests) that refuses it.
func TestEveryWriteIsBoundToTheAuthenticatedUser(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		route route
		// owner returns the owner argument of each statement.
		argAt []int
	}{
		nameCreate: {route: route{pathCollection, http.MethodPost, "", bodyNameA}, argAt: []int{4, -1}},
		nameRename: {route: route{pathItem, http.MethodPatch, otherAgentID, bodyNameA}, argAt: []int{2}},
		nameRevoke: {route: route{pathItem, http.MethodDelete, otherAgentID, ""}, argAt: []int{2, 2}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			fix.batcher.rows = [][]any{columns(row(otherAgentID))}

			rt := tt.route
			_, _ = fix.call(t, rt.path, rt.method, rt.id, rt.body)

			if len(fix.batcher.batches) != 1 {
				t.Fatalf("ran %d batches, want 1", len(fix.batcher.batches))
			}

			for i, at := range tt.argAt {
				if at < 0 {
					continue
				}

				if got := fix.batcher.batches[0][i].Args[at]; got != testUserID {
					t.Errorf("statement %d binds owner %v, want the session's user %s", i, got, testUserID)
				}
			}
		})
	}
}

const otherAgentID = "00000000-0000-7000-8000-0000000000e1"

// TestTheSessionsUserIsNeverTakenFromThePath: a path or body that names another
// user's id is only ever data. Ids are validated for shape, so nothing but a
// canonical lowercase UUID reaches SQL.
func TestAgentIDsAreCheckedForShapeBeforeAnyRead(t *testing.T) {
	t.Parallel()

	ids := map[string]string{
		"empty":            "",
		"sql comment":      "00000000-0000-7000-8000-0000000000--",
		"sql injection":    "' OR '1'='1",
		"wildcard":         "%",
		"too long":         testAgentID + "0",
		"embedded newline": "00000000-0000-7000-8000-0000000000a\n",
		"unicode digit":    "00000000-0000-7000-8000-0000000000\u0660\u0660",
		"uppercase":        strings.ToUpper(testAgentID),
		"no dashes":        strings.ReplaceAll(testAgentID, "-", "0")[:36],
	}

	routes := map[string]route{
		"get":      {pathItem, http.MethodGet, "", ""},
		nameRename: {pathItem, http.MethodPatch, "", bodyNameA},
		nameRevoke: {pathItem, http.MethodDelete, "", ""},
	}

	for idName, id := range ids {
		for routeName, rt := range routes {
			t.Run(routeName+"/"+idName, func(t *testing.T) {
				t.Parallel()

				fix := newFixture(t)

				_, err := fix.call(t, rt.path, rt.method, id, rt.body)
				wantFailure(t, err, apierr.BadRequest, CodeInvalidID)

				if len(fix.batcher.batches) != 0 || fix.reader.gets != 0 {
					t.Error("a malformed id reached the store")
				}
			})
		}
	}
}

// TestOversizedNamesNeverReachTheDatabase: a name over the limit is refused
// before any insert or update, however it is made large, so the schema's CHECK
// is only ever a backstop. This is the path that would otherwise be a 500.
func TestOversizedNamesNeverReachTheDatabase(t *testing.T) {
	t.Parallel()

	names := map[string]string{
		"one over":           strings.Repeat("a", MaxNameChars+1),
		"multibyte one over": strings.Repeat("é", MaxNameChars+1),
		"astral one over":    strings.Repeat("\U0001F600", MaxNameChars+1),
		"huge":               strings.Repeat("a", 1<<19),
	}

	routes := map[string]route{
		nameCreate: {pathCollection, http.MethodPost, "", ""},
		nameRename: {pathItem, http.MethodPatch, testAgentID, ""},
	}

	for nameName, name := range names {
		for routeName, rt := range routes {
			t.Run(routeName+"/"+nameName, func(t *testing.T) {
				t.Parallel()

				fix := newFixture(t)

				_, err := fix.call(t, rt.path, rt.method, rt.id, `{"name":"`+name+`"}`)
				wantFailure(t, err, apierr.BadRequest, CodeInvalidName)

				if len(fix.batcher.batches) != 0 || len(fix.minter.specs) != 0 {
					t.Error("an oversized name reached the database or minted a key")
				}
			})
		}
	}
}

// TestNamesAtTheLimitAreAccepted pins the boundary from the other side, in
// characters, for every kind of character width.
func TestNamesAtTheLimitAreAccepted(t *testing.T) {
	t.Parallel()

	for name, char := range map[string]string{"ascii": "a", "two bytes": "é", "four bytes": "\U0001F600"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			fix.batcher.rows = [][]any{columns(row(testAgentID))}

			body := `{"name":"` + strings.Repeat(char, MaxNameChars) + `"}`

			for _, rt := range []route{
				{pathCollection, http.MethodPost, "", body},
				{pathItem, http.MethodPatch, testAgentID, body},
			} {
				_, err := fix.call(t, rt.path, rt.method, rt.id, rt.body)
				if err != nil {
					t.Errorf("%s with %d %s = %v, want it accepted", rt.method, MaxNameChars, name, err)
				}
			}
		})
	}
}

// TestAWriteSeesTheStatementsVerdictNotAnEarlierRead: interleaving. The handlers
// never read before they write, so a row that changes between a read and the
// write cannot be acted on stale. The only row a write acts on is the one its
// own statement returned, even when a reader would say otherwise.
func TestAWriteSeesTheStatementsVerdictNotAnEarlierRead(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		route route
		// stale is what the reader would have said before the write.
		stale  Row
		writes Row
		code   string
		kind   apierr.Kind
	}{
		"rename of an agent revoked after the reader looked": {
			route: route{pathItem, http.MethodPatch, testAgentID, `{"name":"x"}`},
			stale: row(testAgentID), writes: withRevoked(row(testAgentID)),
			code: CodeRevoked, kind: apierr.Conflict,
		},
		"revoke of an agent the reader says is gone": {
			route: route{pathItem, http.MethodDelete, testAgentID, ""},
			stale: withRevoked(row(testAgentID)), writes: row(testAgentID),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			fix.store(testUserID, tt.stale)
			fix.batcher.rows = [][]any{columns(tt.writes)}

			rt := tt.route
			_, err := fix.call(t, rt.path, rt.method, rt.id, rt.body)

			if tt.code != "" {
				wantFailure(t, err, tt.kind, tt.code)
			}

			if fix.reader.gets != 0 {
				t.Errorf("read %d times before or after writing, want 0", fix.reader.gets)
			}
		})
	}
}

func withRevoked(r Row) Row {
	r.RevokedAt = new(int64(12345))

	return r
}

// TestACreateThatRacesTheLimitOrARevocationLeavesNothing: the two statements are
// one batch, so the platform failing it means neither was applied. The handler
// reports the conflict and returns no key, so a token for an agent that does not
// exist is never handed out.
func TestACreateThatRacesTheLimitOrARevocationLeavesNothing(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	fix.batcher.err = atomic.ErrConflict

	resp, err := fix.call(t, pathCollection, http.MethodPost, "", createBody)
	wantFailure(t, err, apierr.Conflict, CodeLimit)

	if resp.Body != nil {
		t.Errorf("a failed create returned a body: %v", resp.Body)
	}

	if len(fix.batcher.batches) != 1 || len(fix.batcher.batches[0]) != 2 {
		t.Errorf("batches = %v, want one batch of the agent and its key", fix.batcher.batches)
	}
}

// TestPrincipalWithoutAUserIsStillScoped: an authenticated principal always has
// a user id, but if a verifier ever returned none the writes would bind an empty
// owner, which matches no agent and creates none (users.id is never empty).
func TestAnEmptyUserIDMatchesNothingAndOwnsNothing(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	fix.sessions.principal = session.Principal{UserID: "", Role: ""}
	fix.store(testUserID, row(testAgentID))

	resp, err := fix.call(t, pathCollection, http.MethodGet, "", "")
	if err != nil {
		t.Fatal(err)
	}

	if got := bodyOf(t, resp); got != `{"agents":[]}` {
		t.Errorf("list for an empty user = %s, want none", got)
	}

	_, err = fix.call(t, pathItem, http.MethodGet, testAgentID, "")
	wantFailure(t, err, apierr.NotFound, CodeNotFound)
}

// TestOrdinaryNamesAreAccepted pins what the name rules must not refuse:
// spaces inside a name, punctuation and text in other scripts and emoji.
func TestOrdinaryNamesAreAccepted(t *testing.T) {
	t.Parallel()

	for name, in := range map[string]string{
		"plain":         "assistant",
		"inner spaces":  "my  helper bot",
		"punctuation":   "ci/cd: nightly (v2)",
		"accented":      "agente \u00e9l\u00e8ve",
		"cjk":           "\u30a8\u30fc\u30b8\u30a7\u30f3\u30c8",
		"emoji":         "robot \U0001F916",
		"single char":   "a",
		"quote in name": `say "hi"`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			encoded, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}

			err = validateName(in)
			if err != nil {
				t.Errorf("validateName(%s) = %v, want it accepted", encoded, err)
			}
		})
	}
}

// TestValidateNameRefusesTheReplacementCharacter: httpapi.Decode already
// refuses invalid UTF-8 and lone surrogates, so the replacement character
// cannot arrive through the API. validateName still refuses it, because it is
// what any later decoder would leave in place of bad text.
func TestValidateNameRefusesTheReplacementCharacter(t *testing.T) {
	t.Parallel()

	wantFailure(t, validateName("a\ufffdb"), apierr.BadRequest, CodeInvalidName)
	wantFailure(t, validateName("a\xffb"), apierr.BadRequest, CodeInvalidName)
}
