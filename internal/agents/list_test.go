package agents_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/agents"
	"github.com/susu-dot-dev/authsu/internal/store"
)

const (
	bodyBadLimit  = `{"error":{"code":"invalid_limit","message":"limit must be a single integer from 1 to 100"}}` + "\n"
	bodyBadCursor = `{"error":{"code":"invalid_cursor","message":"cursor must be a single lower-case UUID"}}` + "\n"
)

// TestListPassesItsPageToTheStore: what the query says is what the store is
// asked, for the session's user.
func TestListPassesItsPageToTheStore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		query  string
		cursor string
		limit  int
	}{
		{name: "no parameters", query: "", cursor: "", limit: 25},
		{name: "the smallest limit", query: "?limit=1", cursor: "", limit: 1},
		{name: "the largest limit", query: "?limit=100", cursor: "", limit: 100},
		{name: "a limit in the middle", query: "?limit=42", cursor: "", limit: 42},
		{name: "a cursor", query: "?cursor=" + agentA2, cursor: agentA2, limit: 25},
		{name: "both", query: "?limit=7&cursor=" + agentA3, cursor: agentA3, limit: 7},
		{name: "the other order", query: "?cursor=" + agentA3 + "&limit=7", cursor: agentA3, limit: 7},
		{name: "a parameter that means nothing", query: "?sort=name&limit=3", cursor: "", limit: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodGet, collection+tt.query, "")

			wantOK(t, rg, rec, http.StatusOK, `{"agents":[]}`+"\n")

			want := []storeCall{{method: methodList, owner: userA, cursor: tt.cursor, limit: tt.limit}}
			if len(rg.store.calls) != 1 || rg.store.calls[0] != want[0] {
				t.Errorf("store calls = %+v, want %+v", rg.store.calls, want)
			}
		})
	}
}

// ListResponse is the body of a list.
type ListResponse = agents.ListResponse

// refusedQuery is a list request that is refused, and the exact answer.
type refusedQuery struct {
	name  string
	query string
	body  string
	code  string
}

// badLimit is a query refused for its limit.
func badLimit(name, query string) refusedQuery {
	return refusedQuery{name: name, query: query, body: bodyBadLimit, code: codeLimit}
}

// badCursor is a query refused for its cursor.
func badCursor(name, query string) refusedQuery {
	return refusedQuery{name: name, query: query, body: bodyBadCursor, code: codeCursor}
}

// TestListRefusesWhatItCannotRead: a limit or a cursor that is not exactly
// right is refused, not corrected, and the store is not asked. The first
// invalid value of each parameter is the one reported, whichever comes first
// in the query.
func TestListRefusesWhatItCannotRead(t *testing.T) {
	t.Parallel()

	tests := []refusedQuery{
		badLimit("limit zero", "?limit=0"),
		badLimit("limit over the maximum", "?limit=101"),
		badLimit("limit far over", "?limit=99999999999999999999"),
		badLimit("limit negative", "?limit=-1"),
		badLimit("limit with a plus", "?limit=%2B5"),
		badLimit("limit with a leading zero", "?limit=007"),
		badLimit("limit with leading zeros and a valid value", "?limit=0005"),
		badLimit("limit in hexadecimal", "?limit=0x10"),
		badLimit("limit with a space", "?limit=%205"),
		badLimit("limit not a number", "?limit=abc"),
		badLimit("limit a float", "?limit=1.5"),
		badLimit("limit in an exponent", "?limit=1e1"),
		badLimit("limit in arabic digits", "?limit=%D9%A5"),
		badLimit("limit present but empty", "?limit="),
		badLimit("limit given twice", "?limit=1&limit=2"),
		badLimit("limit given twice, the same", "?limit=5&limit=5"),
		badCursor("cursor upper case", "?cursor="+strings.ToUpper(agentA1)),
		badCursor("cursor not an id", "?cursor=nope"),
		badCursor("cursor the first-page sentinel", "?cursor=g"),
		badCursor("cursor present but empty", "?cursor="),
		badCursor("cursor with a misplaced dash", "?cursor=0000000-00000-7000-8000-0000000000a1"),
		badCursor("cursor with an injection", "?cursor="+url.QueryEscape("' OR '1'='1")),
		badCursor("cursor given twice", "?cursor="+agentA1+"&cursor="+agentA2),
		badLimit("a bad limit and a good cursor", "?limit=0&cursor="+agentA1),
		badCursor("a good limit and a bad cursor", "?limit=5&cursor=x"),
		badLimit("both bad: the limit is reported", "?cursor=x&limit=0"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(agentA1, nameAlpha, 1, nil))

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodGet, collection+tt.query, "")

			wantFailure(t, rg, rec, http.StatusBadRequest, tt.body, tt.code)
			rg.untouched()
		})
	}
}

// TestListPages: one page, the next, and the last, with the cursor present
// exactly while there is another page.
func TestListPages(t *testing.T) {
	t.Parallel()

	oldest := stored(agentA1, "oldest", 100, nil)
	middle := stored(agentA2, "middle", 200, new(int64(300)))
	newest := stored(agentA3, "newest", 400, nil)

	// The three as a client sees them, newest first.
	jsonNewest := agentJSON(agentA3, "newest", 400, nil)
	jsonMiddle := agentJSON(agentA2, "middle", 200, new(int64(300)))
	jsonOldest := agentJSON(agentA1, "oldest", 100, nil)

	tests := []struct {
		name  string
		query string
		body  string
	}{
		{
			name: "the first page has a next", query: "?limit=2",
			body: `{"agents":[` + jsonNewest + `,` + jsonMiddle +
				`],"next":"` + agentA2 + `"}`,
		},
		{
			name: "the last page has none", query: "?limit=2&cursor=" + agentA2,
			body: `{"agents":[` + jsonOldest + `]}`,
		},
		{
			name: "exactly one page: no next", query: "?limit=3",
			body: `{"agents":[` + jsonNewest + `,` + jsonMiddle +
				`,` + jsonOldest + `]}`,
		},
		{
			name: "a page of one", query: "?limit=1&cursor=" + agentA3,
			body: `{"agents":[` + jsonMiddle + `],"next":"` + agentA2 + `"}`,
		},
		{name: "past the end", query: "?cursor=" + agentA1, body: `{"agents":[]}`},
		{
			name: "the default limit returns them all", query: "",
			body: `{"agents":[` + jsonNewest + `,` + jsonMiddle +
				`,` + jsonOldest + `]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, oldest, middle, newest)

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodGet, collection+tt.query, "")

			wantOK(t, rg, rec, http.StatusOK, tt.body+"\n")
		})
	}
}

// storeFailure is a failure of the store and what the client is told for it.
type storeFailure struct {
	name string
	// err is what the store returns.
	err    error
	status int
	body   string
	// logged is the code the log carries.
	logged string
}

// storeFailures are the ways the store fails for an operation whose codes are
// failed and rejected. A classified failure is sent as it is, an Internal one
// as the bare "internal", and a failure that was never classified is Internal
// too: nothing about the cause reaches the client.
func storeFailures(failed, rejected string) []storeFailure {
	return []storeFailure{
		{
			name: "the database is unavailable", err: unavailableErr(failed),
			status: http.StatusServiceUnavailable, body: errorBody(failed, "agents are temporarily unavailable"), logged: failed,
		},
		{
			name: "the schema rejected the write", err: internalErr(rejected),
			status: http.StatusInternalServerError, body: bodyInternal, logged: rejected,
		},
		{
			name: "an error nobody classified", err: errDB,
			status: http.StatusInternalServerError, body: bodyInternal, logged: "internal",
		},
	}
}

// TestStoreFailuresReachTheClientAsTheStoreClassifiedThem: every store method of
// every route, failing every way.
func TestStoreFailuresReachTheClientAsTheStoreClassifiedThem(t *testing.T) {
	t.Parallel()

	operations := []struct {
		route    agentRoute
		method   string
		failed   string
		rejected string
	}{
		{
			route:  agentRoute{name: routeList, method: http.MethodGet, target: collection, body: ""},
			method: methodList, failed: store.CodeAgentListFailed, rejected: store.CodeAgentListRejected,
		},
		{
			route:  agentRoute{name: routeGet, method: http.MethodGet, target: itemPrefix + agentA1, body: ""},
			method: methodGet, failed: store.CodeAgentLookupFailed, rejected: store.CodeAgentLookupRejected,
		},
		{
			route:  agentRoute{name: routeCreate, method: http.MethodPost, target: collection, body: bodyAssistant},
			method: methodCreate, failed: store.CodeAgentCreateFailed, rejected: store.CodeAgentCreateRejected,
		},
		{
			route:  agentRoute{name: routeRename, method: http.MethodPatch, target: itemPrefix + agentA1, body: bodyX},
			method: methodRename, failed: store.CodeAgentUpdateFailed, rejected: store.CodeAgentUpdateRejected,
		},
		{
			route:  agentRoute{name: routeRevoke, method: http.MethodDelete, target: itemPrefix + agentA1, body: ""},
			method: methodRevoke, failed: store.CodeAgentRevokeFailed, rejected: store.CodeAgentRevokeRejected,
		},
	}

	for _, op := range operations {
		for _, failure := range storeFailures(op.failed, op.rejected) {
			t.Run(op.route.name+"/"+failure.name, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				rg.seed(userA, stored(agentA1, nameAlpha, 1, nil))
				rg.store.failures[op.method] = failure.err

				rec := rg.as(rg.signIn(userA, roleMember), op.route.method, op.route.target, op.route.body)

				wantFailure(t, rg, rec, failure.status, failure.body, failure.logged)

				if got := rg.store.agent(t, agentA1); got != stored(agentA1, nameAlpha, 1, nil) {
					t.Errorf("a failed request changed the agent to %+v", got)
				}
			})
		}
	}
}

// TestPagesCoverEveryAgentOnce follows the cursors of a user's agents, at every
// page size, and sees each agent exactly once, newest first, with no page
// after the last and a cursor on every page before it.
func TestPagesCoverEveryAgentOnce(t *testing.T) {
	t.Parallel()

	const total = 7

	ids := make([]string, total)
	for i := range ids {
		ids[i] = fmt.Sprintf("00000000-0000-7000-8000-0000000001%02d", i)
	}

	want := slices.Clone(ids)
	slices.Reverse(want)

	for size := 1; size <= total+1; size++ {
		t.Run(fmt.Sprintf("page size %d", size), func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)

			for i, id := range ids {
				rg.seed(userA, stored(id, "agent", int64(i), nil))
			}

			seen := walkPages(t, rg, rg.signIn(userA, roleMember), size, total)

			if !slices.Equal(seen, want) {
				t.Errorf("paging saw %v, want every agent once, newest first: %v", seen, want)
			}
		})
	}
}

// walkPages follows the list's cursors with pages of size, and returns the ids
// it saw in order. It fails if a page is larger than size, if a cursor is not
// the last agent of its page, or if the cursors do not end within maxPages.
func walkPages(t *testing.T, rg *rig, cookie *http.Cookie, size, maxPages int) []string {
	t.Helper()

	var (
		seen   []string
		cursor string
	)

	for range maxPages + 1 {
		rec := rg.as(cookie, http.MethodGet, fmt.Sprintf("%s?limit=%d%s", collection, size, cursor), "")

		var page ListResponse

		err := json.Unmarshal(rec.Body.Bytes(), &page)
		if rec.Code != http.StatusOK || err != nil || len(page.Agents) > size {
			t.Fatalf("a page = %d %q (%v), want at most %d agents", rec.Code, rec.Body.String(), err, size)
		}

		for _, agent := range page.Agents {
			seen = append(seen, agent.ID)
		}

		if page.Next == "" {
			return seen
		}

		if page.Next != page.Agents[len(page.Agents)-1].ID {
			t.Fatalf("next = %s, want the last agent of the page", page.Next)
		}

		cursor = "&cursor=" + page.Next
	}

	t.Fatal("paging did not end")

	return nil
}
