package users

import (
	"net/http"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/session"
)

// route is one account route and the id it is called with.
type route struct {
	path   string
	method string
	id     string
}

func allRoutes() map[string]route {
	return map[string]route{
		"list":   {path: "collection", method: http.MethodGet, id: ""},
		"get":    {path: "item", method: http.MethodGet, id: testUserID},
		"revoke": {path: "item", method: http.MethodDelete, id: testUserID},
	}
}

// TestEveryRouteRequiresAnAdmin runs each route as someone who is not signed
// in, as someone signed in who is not an admin, and with sessions unavailable,
// and checks that nothing is read or written before the refusal.
func TestEveryRouteRequiresAnAdmin(t *testing.T) {
	t.Parallel()

	actors := map[string]struct {
		principal session.Principal
		err       error
		kind      apierr.Kind
		code      string
	}{
		"not signed in": {
			err:  apierr.New(apierr.Unauthorized, session.CodeUnauthenticated, "not signed in"),
			kind: apierr.Unauthorized, code: session.CodeUnauthenticated,
		},
		"sessions unavailable": {
			err:  apierr.New(apierr.Unavailable, session.CodeNotConfigured, "sessions are not available"),
			kind: apierr.Unavailable, code: session.CodeNotConfigured,
		},
		"signed in, not an admin": {
			principal: session.Principal{UserID: testAdminID, Role: roleMember},
			kind:      apierr.Forbidden, code: CodeForbidden,
		},
		"signed in, no role": {
			principal: session.Principal{UserID: testAdminID, Role: ""},
			kind:      apierr.Forbidden, code: CodeForbidden,
		},
	}

	for routeName, rt := range allRoutes() {
		for actorName, actor := range actors {
			t.Run(routeName+"/"+actorName, func(t *testing.T) {
				t.Parallel()

				fix := newFixture(t)
				fix.sessions.principal, fix.sessions.err = actor.principal, actor.err
				fix.store(row(testUserID))

				handler := fix.svc.Handlers(getenv).forMethod(rt.path, rt.method)

				_, err := handler(request(t, rt.method, rt.id)).Get()
				wantFailure(t, err, actor.kind, actor.code)

				if len(fix.batcher.batches) != 0 || fix.reader.gets != 0 {
					t.Errorf("a refused request touched the store: %d batches, %d reads",
						len(fix.batcher.batches), fix.reader.gets)
				}
			})
		}
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
			svc := NewService(Deps{Sessions: fix.sessions, Reader: nil, Batch: nil, Now: testNow})

			_, err := svc.Handlers(getenv).forMethod(rt.path, rt.method)(request(t, rt.method, rt.id)).Get()
			wantFailure(t, err, apierr.Unavailable, CodeNotConfigured)

			if fix.sessions.calls != 0 {
				t.Error("authenticated against a missing store")
			}
		})
	}
}

// TestRevokeNeedsABatch: a reader but no batch function disables revocation,
// after the caller has been authorised. Reads still work.
func TestRevokeNeedsABatch(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	svc := NewService(Deps{Sessions: fix.sessions, Reader: fix.reader, Batch: nil, Now: testNow})

	_, err := svc.Handlers(getenv).Item[http.MethodDelete](request(t, http.MethodDelete, testUserID)).Get()
	wantFailure(t, err, apierr.Unavailable, CodeNotConfigured)

	if fix.sessions.calls != 1 {
		t.Errorf("authenticated %d times, want once", fix.sessions.calls)
	}

	_, err = svc.Handlers(getenv).Collection[http.MethodGet](request(t, http.MethodGet, "")).Get()
	if err != nil {
		t.Errorf("list without a batch = %v, want it to work", err)
	}
}
