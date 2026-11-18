package agents

import (
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/apierr"
)

// The query parameters of a list.
const (
	keyLimit  = "limit"
	keyCursor = "cursor"
)

const otherUserID = "00000000-0000-7000-8000-000000000003"

// agentN is the id of the nth agent. UUIDv7 ids are in creation order, so a
// larger n is a newer agent.
func agentN(n int) string {
	return fmt.Sprintf("00000000-0000-7000-8000-%012x", n)
}

func TestListReturnsTheCallersAgentsNewestFirstAndOnlyTheirs(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	revoked := row(agentN(0xa2))
	revoked.RevokedAt = new(int64(12345))

	fix.store(testUserID, row(agentN(0xa1)))
	fix.store(otherUserID, row(agentN(0xa9)))
	fix.store(testUserID, revoked)

	resp, err := fix.list(t, nil)
	if err != nil {
		t.Fatal(err)
	}

	out, _ := resp.Body.(ListResponse)
	want := []Agent{present(revoked), present(row(agentN(0xa1)))}

	if !reflect.DeepEqual(out.Agents, want) {
		t.Errorf("agents = %+v, want %+v", out.Agents, want)
	}

	if out.Agents[0].Status != StatusRevoked || out.Agents[1].Status != StatusActive {
		t.Errorf("statuses = %q, %q, want revoked then active", out.Agents[0].Status, out.Agents[1].Status)
	}

	if !reflect.DeepEqual(fix.reader.askedFor, []string{testUserID}) {
		t.Errorf("read for %v, want only the caller", fix.reader.askedFor)
	}
}

// TestListIsAnEmptyArrayNotNull: a client iterating the list must not have to
// special-case a user with no agents.
func TestListIsAnEmptyArrayNotNull(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	resp, err := fix.list(t, nil)
	if err != nil {
		t.Fatal(err)
	}

	if got := bodyOf(t, resp); got != `{"agents":[]}` {
		t.Errorf("body = %s, want {\"agents\":[]}", got)
	}
}

// TestListPaging walks the pages of a user's agents. Each case stores agents 1
// to total and asks for one page, and says which agents it must hold and what
// cursor it must offer.
func TestListPaging(t *testing.T) {
	t.Parallel()

	for name, tt := range pagingCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			for n := 1; n <= tt.total; n++ {
				fix.store(testUserID, row(agentN(n)))
			}

			resp, err := fix.list(t, tt.query)
			if err != nil {
				t.Fatal(err)
			}

			out, _ := resp.Body.(ListResponse)
			if len(out.Agents) != tt.count || out.Next != tt.next {
				t.Fatalf("page = %d agents, next %q, want %d, %q", len(out.Agents), out.Next, tt.count, tt.next)
			}

			if tt.count > 0 && (out.Agents[0].ID != agentN(tt.first) || out.Agents[tt.count-1].ID != agentN(tt.last)) {
				t.Errorf("page runs %s to %s, want %s to %s", out.Agents[0].ID, out.Agents[tt.count-1].ID,
					agentN(tt.first), agentN(tt.last))
			}
		})
	}
}

type pagingCase struct {
	total int
	query map[string][]string
	// first and last are the numbers of the newest and oldest agent on the
	// page; none is 0.
	first, last int
	count       int
	next        string
}

func pagingCases() map[string]pagingCase {
	return map[string]pagingCase{
		"default size, fewer than a page": {total: 3, query: nil, first: 3, last: 1, count: 3, next: ""},
		"exactly a page has no next": {
			total: 5, query: map[string][]string{keyLimit: {"5"}}, first: 5, last: 1, count: 5, next: "",
		},
		"one more than a page has a next": {
			total: 6, query: map[string][]string{keyLimit: {"5"}}, first: 6, last: 2, count: 5, next: agentN(2),
		},
		"limit 1": {total: 3, query: map[string][]string{keyLimit: {"1"}}, first: 3, last: 3, count: 1, next: agentN(3)},
		"cursor starts below it": {
			total: 6, query: map[string][]string{keyLimit: {"2"}, keyCursor: {agentN(4)}},
			first: 3, last: 2, count: 2, next: agentN(2),
		},
		"cursor at the oldest is empty": {
			total: 3, query: map[string][]string{keyCursor: {agentN(1)}}, first: 0, last: 0, count: 0, next: "",
		},
		"cursor above the newest is the first page": {
			total: 2, query: map[string][]string{keyCursor: {agentN(99)}}, first: 2, last: 1, count: 2, next: "",
		},
		"max limit": {
			total: MaxPageSize + 1, query: map[string][]string{keyLimit: {strconv.Itoa(MaxPageSize)}},
			first: MaxPageSize + 1, last: 2, count: MaxPageSize, next: agentN(2),
		},
		"default size caps the page": {
			total: DefaultPageSize + 1, query: nil,
			first: DefaultPageSize + 1, last: 2, count: DefaultPageSize, next: agentN(2),
		},
	}
}

// TestListPagesCoverEveryAgentOnce follows next from the first page to the end:
// every agent appears exactly once, in order, whatever the page size.
func TestListPagesCoverEveryAgentOnce(t *testing.T) {
	t.Parallel()

	const total = 11

	for size := 1; size <= total+1; size++ {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			for n := 1; n <= total; n++ {
				fix.store(testUserID, row(agentN(n)))
			}

			var seen []string

			cursor := ""

			for range total + 1 {
				query := map[string][]string{keyLimit: {strconv.Itoa(size)}}
				if cursor != "" {
					query["cursor"] = []string{cursor}
				}

				resp, err := fix.list(t, query)
				if err != nil {
					t.Fatal(err)
				}

				out, _ := resp.Body.(ListResponse)
				for _, agent := range out.Agents {
					seen = append(seen, agent.ID)
				}

				if cursor = out.Next; cursor == "" {
					break
				}
			}

			if len(seen) != total {
				t.Fatalf("saw %d agents, want %d: %v", len(seen), total, seen)
			}

			if !sort.IsSorted(sort.Reverse(sort.StringSlice(seen))) {
				t.Errorf("pages are not newest first: %v", seen)
			}
		})
	}
}

// TestListRefusesABadQueryBeforeAuthenticating: the limit and cursor are
// refused, not corrected, and nothing is read for a request that is refused.
func TestListRefusesABadQueryBeforeAuthenticating(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		query map[string][]string
		code  string
	}{
		"limit zero":            {map[string][]string{keyLimit: {"0"}}, CodeInvalidLimit},
		"limit over the max":    {map[string][]string{keyLimit: {strconv.Itoa(MaxPageSize + 1)}}, CodeInvalidLimit},
		"limit negative":        {map[string][]string{keyLimit: {"-1"}}, CodeInvalidLimit},
		"limit signed":          {map[string][]string{keyLimit: {"+5"}}, CodeInvalidLimit},
		"limit empty":           {map[string][]string{keyLimit: {""}}, CodeInvalidLimit},
		"limit text":            {map[string][]string{keyLimit: {"ten"}}, CodeInvalidLimit},
		"limit decimal":         {map[string][]string{keyLimit: {"1.5"}}, CodeInvalidLimit},
		"limit hex":             {map[string][]string{keyLimit: {"0x10"}}, CodeInvalidLimit},
		"limit padded":          {map[string][]string{keyLimit: {" 5"}}, CodeInvalidLimit},
		"limit too many digits": {map[string][]string{keyLimit: {"0005"}}, CodeInvalidLimit},
		"limit past int64":      {map[string][]string{keyLimit: {"99999999999999999999"}}, CodeInvalidLimit},
		"limit twice":           {map[string][]string{keyLimit: {"1", "2"}}, CodeInvalidLimit},
		"cursor empty":          {map[string][]string{keyCursor: {""}}, CodeInvalidCursor},
		"cursor text":           {map[string][]string{keyCursor: {badID}}, CodeInvalidCursor},
		"cursor uppercase":      {map[string][]string{keyCursor: {strings.ToUpper(testAgentID)}}, CodeInvalidCursor},
		"cursor the sentinel":   {map[string][]string{keyCursor: {FirstPage}}, CodeInvalidCursor},
		"cursor twice":          {map[string][]string{keyCursor: {testAgentID, testAgentID}}, CodeInvalidCursor},
		"cursor with sql":       {map[string][]string{keyCursor: {"' OR 1=1 --"}}, CodeInvalidCursor},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)

			_, err := fix.list(t, tt.query)
			wantFailure(t, err, apierr.BadRequest, tt.code)

			if fix.sessions.calls != 0 || fix.reader.lists != 0 {
				t.Errorf("a refused query authenticated %d times and read %d", fix.sessions.calls, fix.reader.lists)
			}
		})
	}
}

// TestListAsksForOneMoreThanThePage pins how the next page is found: one extra
// row, from the cursor, for the caller.
func TestListAsksForOneMoreThanThePage(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	_, err := fix.list(t, map[string][]string{keyLimit: {"7"}, keyCursor: {testAgentID}})
	if err != nil {
		t.Fatal(err)
	}

	want := []pageAsked{{before: testAgentID, limit: 8}}
	if !reflect.DeepEqual(fix.reader.pages, want) {
		t.Errorf("asked for %+v, want %+v", fix.reader.pages, want)
	}

	fix = newFixture(t)

	_, err = fix.list(t, nil)
	if err != nil {
		t.Fatal(err)
	}

	want = []pageAsked{{before: FirstPage, limit: DefaultPageSize + 1}}
	if !reflect.DeepEqual(fix.reader.pages, want) {
		t.Errorf("default asked for %+v, want %+v", fix.reader.pages, want)
	}
}

func TestListFailsWhenTheStoreDoes(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	fix.reader.listErr = errDB

	_, err := fix.list(t, nil)
	wantFailure(t, err, apierr.Unavailable, CodeListFailed)
}

func TestGetReturnsTheCallersAgent(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	fix.store(testUserID, row(testAgentID))

	resp, err := fix.call(t, pathItem, http.MethodGet, testAgentID, "")
	if err != nil {
		t.Fatal(err)
	}

	want := `{"id":"` + testAgentID + `","name":"assistant","scopes":"default:agent","status":"active",` +
		`"createdAt":` + itoa(testNow().Unix()-100) + `}`

	if got := bodyOf(t, resp); got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
}

func TestGetShowsARevocationTime(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)

	revoked := row(testAgentID)
	revoked.RevokedAt = new(int64(12345))
	fix.store(testUserID, revoked)

	resp, err := fix.call(t, pathItem, http.MethodGet, testAgentID, "")
	if err != nil {
		t.Fatal(err)
	}

	if got := bodyOf(t, resp); !contains(got, `"status":"revoked"`, `"revokedAt":12345`) {
		t.Errorf("body = %s, want a revoked agent with its time", got)
	}
}

// TestAnotherUsersAgentIsNotFound: an agent of someone else is answered exactly
// as one that does not exist, so ids reveal nothing about other accounts.
func TestAnotherUsersAgentIsNotFound(t *testing.T) {
	t.Parallel()

	fix := newFixture(t)
	fix.store(otherUserID, row(testAgentID))

	_, err := fix.call(t, pathItem, http.MethodGet, testAgentID, "")
	wantFailure(t, err, apierr.NotFound, CodeNotFound)
}

func TestGetFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		id     string
		getErr error
		kind   apierr.Kind
		code   string
	}{
		"unknown":        {id: testAgentID, kind: apierr.NotFound, code: CodeNotFound},
		"store is down":  {id: testAgentID, getErr: errDB, kind: apierr.Unavailable, code: CodeLookupFailed},
		"missing id":     {id: "", kind: apierr.BadRequest, code: CodeInvalidID},
		"not a uuid":     {id: badID, kind: apierr.BadRequest, code: CodeInvalidID},
		"a quote":        {id: "00000000-0000-7000-8000-0000000000a'", kind: apierr.BadRequest, code: CodeInvalidID},
		"uppercase":      {id: "00000000-0000-7000-8000-0000000000AA", kind: apierr.BadRequest, code: CodeInvalidID},
		"one char short": {id: testAgentID[1:], kind: apierr.BadRequest, code: CodeInvalidID},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fix := newFixture(t)
			fix.reader.getErr = tt.getErr

			_, err := fix.call(t, pathItem, http.MethodGet, tt.id, "")
			wantFailure(t, err, tt.kind, tt.code)
		})
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestStatusOf(t *testing.T) {
	t.Parallel()

	if got := StatusOf(row(testAgentID)); got != StatusActive {
		t.Errorf("StatusOf(active) = %q", got)
	}

	// Any revoked_at at all revokes, even one in the future.
	revoked := row(testAgentID)
	revoked.RevokedAt = new(testNow().Unix() + 1_000_000)

	if got := StatusOf(revoked); got != StatusRevoked {
		t.Errorf("StatusOf(revoked) = %q", got)
	}
}
