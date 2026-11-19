package keys_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/keys"
	"github.com/susu-dot-dev/authsu/internal/store"
)

const (
	bodyNoKeys    = `{"keys":[]}`
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
		{name: "a cursor", query: "?cursor=" + keyA2, cursor: keyA2, limit: 25},
		{name: "both", query: "?limit=7&cursor=" + keyA3, cursor: keyA3, limit: 7},
		{name: "the other order", query: "?cursor=" + keyA3 + "&limit=7", cursor: keyA3, limit: 7},
		{name: "a parameter that means nothing", query: "?sort=name&limit=3", cursor: "", limit: 3},
		{name: "an agent filter is not a thing here", query: "?agent=" + agentA1, cursor: "", limit: 25},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodGet, collection+tt.query, "")

			wantOK(t, rg, rec, bodyNoKeys+"\n")

			want := []storeCall{{method: methodList, owner: userA, cursor: tt.cursor, limit: tt.limit}}
			if !reflect.DeepEqual(rg.store.calls, want) {
				t.Errorf("store calls = %+v, want %+v", rg.store.calls, want)
			}
		})
	}
}

// TestListRefusesWhatItCannotRead: a limit or a cursor that is not exactly right
// is refused, not corrected, and the store is not asked.
func TestListRefusesWhatItCannotRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, query, body, code string
	}{
		{"limit zero", "?limit=0", bodyBadLimit, codeLimit},
		{"limit over the maximum", "?limit=101", bodyBadLimit, codeLimit},
		{"limit far over", "?limit=99999999999999999999", bodyBadLimit, codeLimit},
		{"limit negative", "?limit=-1", bodyBadLimit, codeLimit},
		{"limit with a plus", "?limit=%2B5", bodyBadLimit, codeLimit},
		{"limit with a leading zero", "?limit=007", bodyBadLimit, codeLimit},
		{"limit in hexadecimal", "?limit=0x10", bodyBadLimit, codeLimit},
		{"limit with a space", "?limit=%205", bodyBadLimit, codeLimit},
		{"limit a float", "?limit=1.5", bodyBadLimit, codeLimit},
		{"limit present but empty", "?limit=", bodyBadLimit, codeLimit},
		{"limit given twice", "?limit=1&limit=2", bodyBadLimit, codeLimit},
		{"cursor upper case", "?cursor=" + strings.ToUpper(keyA1), bodyBadCursor, codeCursor},
		{"cursor not an id", "?cursor=nope", bodyBadCursor, codeCursor},
		{"cursor the first-page sentinel", "?cursor=g", bodyBadCursor, codeCursor},
		{"cursor present but empty", "?cursor=", bodyBadCursor, codeCursor},
		{"cursor with an injection", "?cursor=" + url.QueryEscape("' OR '1'='1"), bodyBadCursor, codeCursor},
		{"cursor given twice", "?cursor=" + keyA1 + "&cursor=" + keyA2, bodyBadCursor, codeCursor},
		{"both bad: the limit is reported", "?cursor=x&limit=0", bodyBadLimit, codeLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(keyA1, nameCI, 1, nil))

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodGet, collection+tt.query, "")

			wantFailure(t, rg, rec, http.StatusBadRequest, tt.body, tt.code)
			rg.untouched()
		})
	}
}

// TestListPages: one page, the next, and the last, with the cursor present
// exactly while there is another page, and each key's status derived at the
// request's clock.
func TestListPages(t *testing.T) {
	t.Parallel()

	oldest := stored(keyA1, "oldest", 100, nil)
	middle := stored(keyA2, "middle", 200, new(int64(300)))
	newest := stored(keyA3, "newest", 400, nil)

	jsonNewest := keyJSON(keyA3, "newest", 400, nil)
	jsonMiddle := keyJSON(keyA2, "middle", 200, new(int64(300)))
	jsonOldest := keyJSON(keyA1, "oldest", 100, nil)

	tests := []struct {
		name  string
		query string
		body  string
	}{
		{
			name: "the first page has a next", query: "?limit=2",
			body: `{"keys":[` + jsonNewest + `,` + jsonMiddle + `],"next":"` + keyA2 + `"}`,
		},
		{name: "the last page has none", query: "?limit=2&cursor=" + keyA2, body: `{"keys":[` + jsonOldest + `]}`},
		{
			name: "exactly one page: no next", query: "?limit=3",
			body: `{"keys":[` + jsonNewest + `,` + jsonMiddle + `,` + jsonOldest + `]}`,
		},
		{name: "a page of one", query: "?limit=1&cursor=" + keyA3,
			body: `{"keys":[` + jsonMiddle + `],"next":"` + keyA2 + `"}`},
		{name: "past the end", query: "?cursor=" + keyA1, body: bodyNoKeys},
		{
			name: "the default limit returns them all", query: "",
			body: `{"keys":[` + jsonNewest + `,` + jsonMiddle + `,` + jsonOldest + `]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, oldest, middle, newest)

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodGet, collection+tt.query, "")

			wantOK(t, rg, rec, tt.body+"\n")
		})
	}
}

// TestStatusIsDerivedFromTheRowAndTheClock: a key is revoked once it has any
// revocation time at all, expired once its expiry has passed (to the second:
// expiring at now is expired), and active otherwise. Revoked wins over expired.
func TestStatusIsDerivedFromTheRowAndTheClock(t *testing.T) {
	t.Parallel()

	rg0 := newRig(t)
	now := rg0.now.Unix()

	tests := []struct {
		name      string
		expiresAt int64
		revokedAt *int64
		want      keys.Status
	}{
		{"expires in the future", now + 1, nil, keys.StatusActive},
		{"expires this very second", now, nil, keys.StatusExpired},
		{"expired a second ago", now - 1, nil, keys.StatusExpired},
		{"expired long ago", 1, nil, keys.StatusExpired},
		{"revoked, not yet expired", now + 100, new(now - 10), keys.StatusRevoked},
		{"revoked and since expired", now - 1, new(now - 50), keys.StatusRevoked},
		{"revoked this very second", now + 100, new(now), keys.StatusRevoked},
		{"revoked in the future is still active", now + 100, new(now + 5), keys.StatusActive},
		{"revoked in the future and since expired", now - 1, new(now + 5), keys.StatusExpired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)

			key := stored(keyA1, nameCI, 1, tt.revokedAt)
			key.ExpiresAt = tt.expiresAt
			rg.seed(userA, key)

			for _, target := range []string{collection, itemPrefix + keyA1} {
				rec := rg.as(rg.signIn(userA, roleMember), http.MethodGet, target, "")
				if rec.Code != http.StatusOK {
					t.Fatalf("GET %s = %d %s", target, rec.Code, rec.Body)
				}

				if got := statusIn(t, target, rec.Body.Bytes()); got != tt.want {
					t.Errorf("GET %s: status = %q, want %q", target, got, tt.want)
				}
			}
		})
	}
}

// statusIn is the status of the one key in the body of a read: the only member
// of a list, or the key itself.
func statusIn(t *testing.T, target string, body []byte) keys.Status {
	t.Helper()

	if target != collection {
		var key keys.Key

		err := json.Unmarshal(body, &key)
		if err != nil {
			t.Fatalf("body %q: %v", body, err)
		}

		return key.Status
	}

	var page keys.ListResponse

	err := json.Unmarshal(body, &page)
	if err != nil || len(page.Keys) != 1 {
		t.Fatalf("list body %q: %v", body, err)
	}

	return page.Keys[0].Status
}

// TestResponsesNeverCarryASecret: no read returns a token, a hash, an owner or an
// agent, whatever the store holds.
func TestResponsesNeverCarryASecret(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rg.seed(userA, stored(keyA1, nameCI, 1, nil))

	for _, target := range []string{collection, itemPrefix + keyA1} {
		body := rg.as(rg.signIn(userA, roleMember), http.MethodGet, target, "").Body.String()

		for _, forbidden := range []string{"token", "hash", "susu_", "owner", "userId", "agent"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("GET %s returned %q, which contains %q", target, body, forbidden)
			}
		}
	}
}

// TestGet: one key of the caller's, with its fields exactly.
func TestGet(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rg.seed(userA, stored(keyA1, "ci", 100, nil), stored(keyA2, "other", 200, nil))

	rec := rg.as(rg.signIn(userA, roleMember), http.MethodGet, itemPrefix+keyA1, "")

	wantOK(t, rg, rec, keyJSON(keyA1, "ci", 100, nil)+"\n")

	want := []storeCall{{method: methodGet, owner: userA, id: keyA1}}
	if !reflect.DeepEqual(rg.store.calls, want) {
		t.Errorf("store calls = %+v, want %+v", rg.store.calls, want)
	}
}

// TestGetRefusesABadID: a path id that is not a canonical UUID is a 400 after the
// credential is known, and the store is not asked.
func TestGetRefusesABadID(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"a word":              valueNope,
		caseUpper:             strings.ToUpper(keyA1),
		"no dashes":           strings.ReplaceAll(keyA1, "-", ""),
		"trailing characters": keyA1 + "0",
		"a percent-encoded":   keyA1[:35] + "%41",
		"an injection":        url.PathEscape("' OR '1'='1"),
		"a wildcard":          "%25",
	}

	for _, route := range []keyRoute{
		{name: routeGet, method: http.MethodGet, target: itemPrefix, body: ""},
		{name: routePatch, method: http.MethodPatch, target: itemPrefix, body: bodyRenamed},
		{name: routeRevoke, method: http.MethodDelete, target: itemPrefix, body: ""},
	} {
		for name, bad := range tests {
			t.Run(route.name+"/"+name, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				rec := rg.as(rg.signIn(userA, roleMember), route.method, route.target+bad, route.body)

				wantFailure(t, rg, rec, http.StatusBadRequest, bodyInvalidID, codeInvalidID)
				rg.untouched()
			})
		}
	}
}

// TestPagesCoverEveryKeyOnce follows the cursors of a user's keys, at every page
// size, and sees each key exactly once, newest first, with no page after the last
// and a cursor on every page before it.
func TestPagesCoverEveryKeyOnce(t *testing.T) {
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
				rg.seed(userA, stored(id, "key", int64(i), nil))
			}

			seen := walkPages(t, rg, rg.signIn(userA, roleMember), size, total)

			if !slices.Equal(seen, want) {
				t.Errorf("paging saw %v, want every key once, newest first: %v", seen, want)
			}
		})
	}
}

// walkPages follows the list's cursors with pages of size, and returns the ids it
// saw in order.
func walkPages(t *testing.T, rg *rig, cookie *http.Cookie, size, maxPages int) []string {
	t.Helper()

	var (
		seen   []string
		cursor string
	)

	for range maxPages + 1 {
		rec := rg.as(cookie, http.MethodGet, fmt.Sprintf("%s?limit=%d%s", collection, size, cursor), "")

		var page keys.ListResponse

		err := json.Unmarshal(rec.Body.Bytes(), &page)
		if rec.Code != http.StatusOK || err != nil || len(page.Keys) > size {
			t.Fatalf("a page = %d %q (%v), want at most %d keys", rec.Code, rec.Body.String(), err, size)
		}

		for _, key := range page.Keys {
			seen = append(seen, key.ID)
		}

		if page.Next == "" {
			return seen
		}

		if page.Next != page.Keys[len(page.Keys)-1].ID {
			t.Fatalf("next = %s, want the last key of the page", page.Next)
		}

		cursor = "&cursor=" + page.Next
	}

	t.Fatal("paging did not end")

	return nil
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
// failed and rejected. A classified failure is sent as it is, an Internal one as
// the bare "internal", and a failure that was never classified is Internal too:
// nothing about the cause reaches the client.
func storeFailures(failed, rejected string) []storeFailure {
	return []storeFailure{
		{
			name: "the database is unavailable", err: unavailableErr(failed),
			status: http.StatusServiceUnavailable, body: errorBody(failed, "keys are temporarily unavailable"), logged: failed,
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
// every route, failing every way, leaves the stored key as it was.
func TestStoreFailuresReachTheClientAsTheStoreClassifiedThem(t *testing.T) {
	t.Parallel()

	operations := []struct {
		route    keyRoute
		method   string
		failed   string
		rejected string
	}{
		{
			route:  keyRoute{name: routeList, method: http.MethodGet, target: collection, body: ""},
			method: methodList, failed: store.CodeKeyListFailed, rejected: store.CodeKeyListRejected,
		},
		{
			route:  keyRoute{name: routeGet, method: http.MethodGet, target: itemPrefix + keyA1, body: ""},
			method: methodGet, failed: store.CodeKeyLookupFailed, rejected: store.CodeKeyLookupRejected,
		},
		{
			route:  keyRoute{name: routeCreate, method: http.MethodPost, target: collection, body: bodyCI},
			method: methodCreate, failed: store.CodeKeyCreateFailed, rejected: store.CodeKeyCreateRejected,
		},
		{
			route:  keyRoute{name: routePatch, method: http.MethodPatch, target: itemPrefix + keyA1, body: bodyRenamed},
			method: methodRename, failed: store.CodeKeyUpdateFailed, rejected: store.CodeKeyUpdateRejected,
		},
		{
			route:  keyRoute{name: routeRevoke, method: http.MethodDelete, target: itemPrefix + keyA1, body: ""},
			method: methodRevoke, failed: store.CodeKeyRevokeFailed, rejected: store.CodeKeyRevokeRejected,
		},
	}

	for _, op := range operations {
		for _, failure := range storeFailures(op.failed, op.rejected) {
			t.Run(op.route.name+"/"+failure.name, func(t *testing.T) {
				t.Parallel()

				rg := newRig(t)
				rg.seed(userA, stored(keyA1, nameCI, 1, nil))
				rg.store.failures[op.method] = failure.err

				rec := rg.as(rg.signIn(userA, roleMember), op.route.method, op.route.target, op.route.body)

				wantFailure(t, rg, rec, failure.status, failure.body, failure.logged)

				if got := rg.store.key(t, keyA1); !reflect.DeepEqual(got, stored(keyA1, nameCI, 1, nil)) {
					t.Errorf("a failed request changed the key to %+v", got)
				}
			})
		}
	}
}

// TestTheClockIsReadOncePerRequestForTheStatus: a response's status and the time
// a write records come from the same clock the rig controls.
func TestTheClockIsTheRoutesOwn(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	key := stored(keyA1, nameCI, 1, nil)
	key.ExpiresAt = rg.now.Add(time.Hour).Unix()
	rg.seed(userA, key)

	cookie := rg.signIn(userA, roleMember)

	var got keys.Key

	rec := rg.as(cookie, http.MethodGet, itemPrefix+keyA1, "")

	err := json.Unmarshal(rec.Body.Bytes(), &got)
	if err != nil || got.Status != keys.StatusActive {
		t.Fatalf("before: %d %q (%v)", rec.Code, rec.Body.String(), err)
	}

	rg.now = rg.now.Add(2 * time.Hour)

	rec = rg.as(cookie, http.MethodGet, itemPrefix+keyA1, "")

	err = json.Unmarshal(rec.Body.Bytes(), &got)
	if err != nil || got.Status != keys.StatusExpired {
		t.Fatalf("after: %d %q (%v)", rec.Code, rec.Body.String(), err)
	}
}
