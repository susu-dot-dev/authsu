package agents

import (
	"net/http"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/session"
)

// route is one agent route, the id it is called with and a body that passes the
// handler's own validation, so what is under test is the authorisation.
type route struct {
	path   string
	method string
	id     string
	body   string
}

func allRoutes() map[string]route {
	return map[string]route{
		"list":     {path: pathCollection, method: http.MethodGet, id: "", body: ""},
		nameCreate: {path: pathCollection, method: http.MethodPost, id: "", body: bodyNameA},
		"get":      {path: pathItem, method: http.MethodGet, id: testAgentID, body: ""},
		nameRename: {path: pathItem, method: http.MethodPatch, id: testAgentID, body: `{"name":"b"}`},
		nameRevoke: {path: pathItem, method: http.MethodDelete, id: testAgentID, body: ""},
	}
}

// TestEveryRouteRequiresASession runs each route as someone who is not signed
// in and with sessions unavailable, and checks that nothing is read, written or
// minted before the refusal.
func TestEveryRouteRequiresASession(t *testing.T) {
	t.Parallel()

	actors := map[string]struct {
		err  error
		kind apierr.Kind
		code string
	}{
		"not signed in": {
			err:  apierr.New(apierr.Unauthorized, session.CodeUnauthenticated, "not signed in"),
			kind: apierr.Unauthorized, code: session.CodeUnauthenticated,
		},
		"sessions unavailable": {
			err:  apierr.New(apierr.Unavailable, session.CodeNotConfigured, "sessions are not available"),
			kind: apierr.Unavailable, code: session.CodeNotConfigured,
		},
		"an unclassified failure is not signed in": {
			err: errDB, kind: apierr.Unauthorized, code: session.CodeUnauthenticated,
		},
	}

	for routeName, rt := range allRoutes() {
		for actorName, actor := range actors {
			t.Run(routeName+"/"+actorName, func(t *testing.T) {
				t.Parallel()

				fix := newFixture(t)
				fix.sessions.err = actor.err
				fix.store(testUserID, row(testAgentID))

				_, err := fix.call(t, rt.path, rt.method, rt.id, rt.body)
				wantFailure(t, err, actor.kind, actor.code)

				if len(fix.batcher.batches) != 0 || fix.reader.gets+fix.reader.lists != 0 || len(fix.minter.specs) != 0 {
					t.Errorf("a refused request touched the store: %d batches, %d reads, %d mints",
						len(fix.batcher.batches), fix.reader.gets+fix.reader.lists, len(fix.minter.specs))
				}
			})
		}
	}
}

// TestAnyRoleMayUseTheirAgents: there is no role check. An agent is something
// every user has, so an admin, a member and an account with no role are the
// same to this API.
func TestAnyRoleMayUseTheirAgents(t *testing.T) {
	t.Parallel()

	for _, role := range []string{"admin", roleMember, ""} {
		t.Run("role "+role, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			fix.sessions.principal = session.Principal{UserID: testUserID, Role: role}

			_, err := fix.call(t, pathCollection, http.MethodGet, "", "")
			if err != nil {
				t.Errorf("list as %q = %v, want it to work", role, err)
			}
		})
	}
}

// TestRoutesNeedADatabase: with no reader (the host stub has no database) every
// route answers 503 rather than panicking, and does not even authenticate.
func TestRoutesNeedADatabase(t *testing.T) {
	t.Parallel()

	for name, rt := range allRoutes() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			svc := NewService(Deps{
				Sessions: fix.sessions, Reader: nil, Batch: nil, Now: testNow, NewID: nil, Mint: fix.minter.run,
			})

			_, err := svc.Handlers(getenv).forMethod(rt.path, rt.method)(request(t, rt.method, rt.id, rt.body)).Get()
			wantFailure(t, err, apierr.Unavailable, CodeNotConfigured)

			if fix.sessions.calls != 0 {
				t.Error("authenticated against a missing store")
			}
		})
	}
}

// TestWritesNeedABatch: a reader but no batch function disables the routes that
// write, after the caller has been authenticated. Reads still work.
func TestWritesNeedABatch(t *testing.T) {
	t.Parallel()

	for name, rt := range allRoutes() {
		if rt.method == http.MethodGet {
			continue
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			svc := NewService(Deps{
				Sessions: fix.sessions, Reader: fix.reader, Batch: nil, Now: testNow,
				NewID: func() string { return testNewID }, Mint: fix.minter.run,
			})

			_, err := svc.Handlers(getenv).forMethod(rt.path, rt.method)(request(t, rt.method, rt.id, rt.body)).Get()
			wantFailure(t, err, apierr.Unavailable, CodeNotConfigured)

			if fix.sessions.calls != 1 {
				t.Errorf("authenticated %d times, want once", fix.sessions.calls)
			}
		})
	}

	fix := newFixture(t)
	svc := NewService(Deps{Sessions: fix.sessions, Reader: fix.reader, Batch: nil, Now: testNow, NewID: nil, Mint: nil})

	_, err := svc.Handlers(getenv).Collection[http.MethodGet](request(t, http.MethodGet, "", "")).Get()
	if err != nil {
		t.Errorf("list without a batch = %v, want it to work", err)
	}
}

// TestAServiceMissingAFunctionItNeedsCannotWrite: a Deps without a clock, an id
// source or a minter would panic on the first create, so it is treated as not
// configured and no write route runs, rather than failing at request time.
func TestAServiceMissingAFunctionItNeedsCannotWrite(t *testing.T) {
	t.Parallel()

	for missing, mutate := range map[string]func(*Deps){
		"clock":  func(d *Deps) { d.Now = nil },
		"ids":    func(d *Deps) { d.NewID = nil },
		"minter": func(d *Deps) { d.Mint = nil },
	} {
		for name, rt := range allRoutes() {
			if rt.method == http.MethodGet {
				continue
			}

			t.Run(missing+"/"+name, func(t *testing.T) {
				t.Parallel()

				fix := newFixture(t)
				deps := Deps{
					Sessions: fix.sessions, Reader: fix.reader, Batch: fix.batcher.run, Now: testNow,
					NewID: func() string { return testNewID }, Mint: fix.minter.run,
				}
				mutate(&deps)

				_, err := NewService(deps).Handlers(getenv).forMethod(rt.path, rt.method)(
					request(t, rt.method, rt.id, rt.body)).Get()
				wantFailure(t, err, apierr.Unavailable, CodeNotConfigured)

				if len(fix.batcher.batches) != 0 {
					t.Error("a service with a missing dependency wrote")
				}
			})
		}
	}
}
