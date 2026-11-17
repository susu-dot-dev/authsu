package invitations

import (
	"net/http"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/session"
)

// route is one invitation route and a request it accepts.
type route struct {
	method string
	body   any
	id     string
}

func allRoutes() map[string]route {
	return map[string]route{
		"list":   {method: http.MethodGet, body: nil, id: ""},
		"create": {method: http.MethodPost, body: CreateRequest{Type: testType, NumInvites: 1}, id: ""},
		"update": {method: http.MethodPatch, body: UpdateRequest{NumInvites: new(int64(3))}, id: testInvID},
		"revoke": {method: http.MethodDelete, body: nil, id: testInvID},
	}
}

// TestEveryRouteRequiresAnAdmin runs each route as someone who is not signed
// in, as someone signed in who is not an admin, and with sessions unavailable,
// and checks the answer is the same for all of them, before anything is read or
// written.
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
				fix.store(row(testInvID))

				handler := fix.svc.Handlers(getenv).forMethod(rt.method)

				_, err := handler(request(t, rt.method, rt.body, rt.id)).Get()
				wantFailure(t, err, actor.kind, actor.code)

				if len(fix.batcher.batches) != 0 {
					t.Errorf("a refused request wrote: %v", fix.batcher.batches)
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
			svc := NewService(Deps{
				Sessions: fix.sessions, Reader: nil, Batch: nil, Now: testNow, Entropy: fix.entropy,
				NewID: func() string { return testNewID }, Types: []string{testType},
			})

			_, err := svc.Handlers(getenv).forMethod(rt.method)(request(t, rt.method, rt.body, rt.id)).Get()
			wantFailure(t, err, apierr.Unavailable, CodeNotConfigured)

			if fix.sessions.calls != 0 {
				t.Error("authenticated against a missing store")
			}
		})
	}
}

// TestWritesNeedABatch: a reader but no batch function (a platform without D1
// batch support) disables the writes, after the caller has been authorised.
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
				Sessions: fix.sessions, Reader: fix.reader, Batch: nil, Now: testNow, Entropy: fix.entropy,
				NewID: func() string { return testNewID }, Types: []string{testType},
			})

			_, err := svc.Handlers(getenv).forMethod(rt.method)(request(t, rt.method, rt.body, rt.id)).Get()
			wantFailure(t, err, apierr.Unavailable, CodeNotConfigured)
		})
	}
}
