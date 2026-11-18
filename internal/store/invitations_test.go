//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package store_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// invitationID is the id the tests of this file ask for.
const invitationID = "0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b"

// invitationColumns is the number of columns every invitation statement
// returns (not counting the verdict of an update).
const invitationColumns = 9

// Parsers for the input types the invitation operations take, which only their
// parsers can build. They are prefixed because the package's test files share
// one namespace.

func invID(tb testing.TB) input.ID {
	tb.Helper()

	id, err := input.ParseID(invitationID)
	if err != nil {
		tb.Fatalf("parse id %q: %v", invitationID, err)
	}

	return id
}

func invLabel(tb testing.TB, raw string) input.InvitationLabel {
	tb.Helper()

	label, err := input.ParseInvitationLabel(raw)
	if err != nil {
		tb.Fatalf("parse label %q: %v", raw, err)
	}

	return label
}

func invNum(tb testing.TB, raw int64) input.NumInvites {
	tb.Helper()

	num, err := input.ParseNumInvites(raw)
	if err != nil {
		tb.Fatalf("parse num_invites %d: %v", raw, err)
	}

	return num
}

func invExpiry(tb testing.TB, unix int64, at time.Time) *input.Expiry {
	tb.Helper()

	expiry, err := input.ParseExpiry(unix, at)
	if err != nil {
		tb.Fatalf("parse expiry %d: %v", unix, err)
	}

	return &expiry
}

// invitationRow is the row every invitation statement returns: id, type,
// label, num_invites, uses, expires_at, revoked_at, created_by, created_at.
func invitationRow() []any {
	return row(invitationID, "member", "workshop", int64(5), int64(2), int64(1_800_000_000),
		nil, "admin-1", int64(1_700_000_000))
}

// wantInvitation is what invitationRow decodes to.
func wantInvitation() store.Invitation {
	return store.Invitation{
		ID: invitationID, Type: "member", Label: "workshop", NumInvites: 5, Uses: 2,
		ExpiresAt: new(int64(1_800_000_000)), RevokedAt: nil, CreatedBy: new("admin-1"),
		CreatedAt: 1_700_000_000,
	}
}

// invitationOp is one operation that returns an invitation row, so the tables
// that every such operation must pass are written once.
type invitationOp struct {
	name string

	// shape turns an invitation row into the row the operation's statement
	// returns: an update leads its row with the verdict.
	shape func([]any) []any

	// rejected is the operation's code for a malformed result.
	rejected string

	// notFound is whether a result with no row is ErrNotFound. Creating always
	// returns the row it inserted, so for it no row is a defect.
	notFound bool

	// call runs the operation. A list reports its first invitation.
	call func(*store.Store) (store.Invitation, error)
}

func asIs(values []any) []any { return values }

func invitationOps(t *testing.T) []invitationOp {
	t.Helper()

	ctx := context.Background()
	id := invID(t)

	return []invitationOp{
		{name: "list", shape: asIs, rejected: store.CodeInvitationListRejected, notFound: false,
			call: func(s *store.Store) (store.Invitation, error) {
				list, err := s.ListInvitations(ctx)
				if err != nil {
					return store.Invitation{}, fmt.Errorf("list: %w", err)
				}

				if len(list) == 0 {
					return store.Invitation{}, nil
				}

				return list[0], nil
			}},
		{name: "create", shape: asIs, rejected: store.CodeInvitationCreateRejected, notFound: false,
			call: func(s *store.Store) (store.Invitation, error) { return s.CreateInvitation(ctx, newInvitation(t)) }},
		{name: "update", shape: func(values []any) []any { return withVerdict(int64(1), values) },
			rejected: store.CodeInvitationUpdateRejected, notFound: true,
			call: func(s *store.Store) (store.Invitation, error) {
				invitation, _, err := s.UpdateNumInvites(ctx, id, invNum(t, 5))
				if err != nil {
					return store.Invitation{}, fmt.Errorf("update: %w", err)
				}

				return invitation, nil
			}},
		{name: "revoke", shape: asIs, rejected: store.CodeInvitationRevokeRejected, notFound: true,
			call: func(s *store.Store) (store.Invitation, error) { return s.RevokeInvitation(ctx, id, now) }},
	}
}

// newInvitation is a valid invitation to create.
func newInvitation(t *testing.T) store.NewInvitation {
	t.Helper()

	return store.NewInvitation{
		ID: invitationID, CodeHash: invHash(), Type: "member", Label: invLabel(t, "workshop"),
		NumInvites: invNum(t, 5), ExpiresAt: invExpiry(t, now.Unix()+3600, now), CreatedBy: "admin-1", CreatedAt: now,
	}
}

// invHash is a code hash: 32 bytes.
func invHash() []byte { return []byte("0123456789abcdef0123456789abcdef") }

// TestInvitationDecoding holds how a returned row becomes an Invitation, for
// every operation that returns one.
func TestInvitationDecoding(t *testing.T) {
	t.Parallel()

	revoked := wantInvitation()
	revoked.RevokedAt = new(int64(1_700_000_050))

	bare := wantInvitation()
	bare.ExpiresAt, bare.CreatedBy = nil, nil

	extreme := wantInvitation()
	extreme.NumInvites, extreme.Uses, extreme.CreatedAt = 1<<53-1, 1<<53-1, 1<<53-1
	extreme.ExpiresAt = new(int64(1<<53 - 1))
	extreme.CreatedBy = new("admin-1")

	empty := wantInvitation()
	empty.Label, empty.Uses = "", 0

	multibyte := wantInvitation()
	multibyte.Label = "naïve ☕ Ωμέγα"

	tests := []struct {
		name string
		row  []any
		want store.Invitation
	}{
		{name: "every column set", row: invitationRow(), want: wantInvitation()},
		{name: "a revoked invitation", row: with(invitationRow(), 6, int64(1_700_000_050)), want: revoked},
		{name: "no expiry and no creator (the first-run invitation)",
			row: with(with(invitationRow(), 5, nil), 7, nil), want: bare},
		{name: "empty label and no uses", row: with(with(invitationRow(), 2, ""), 4, int64(0)), want: empty},
		{name: "a multibyte label", row: with(invitationRow(), 2, "naïve ☕ Ωμέγα"), want: multibyte},
		{name: "integers at the largest value JavaScript holds exactly",
			row: row(invitationID, "member", "workshop", int64(1<<53-1), int64(1<<53-1), int64(1<<53-1),
				nil, "admin-1", int64(1<<53-1)),
			want: extreme},
	}

	for _, operation := range invitationOps(t) {
		for _, test := range tests {
			t.Run(operation.name+"/"+test.name, func(t *testing.T) {
				t.Parallel()

				fake := newFake(returning(operation.shape(test.row)))

				got, err := operation.call(fake.store())

				checkErr(t, err, nil)

				if !reflect.DeepEqual(got, test.want) {
					t.Errorf("invitation = %+v, want %+v", got, test.want)
				}
			})
		}
	}
}

// TestInvitationDefects holds that a row that is not the invitation row the
// query promises is a defect, never a partial invitation: an admin must not be
// shown (or act on) an invitation read from a broken row.
func TestInvitationDefects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		row  []any
	}{
		{name: "id is NULL", row: with(invitationRow(), 0, nil)},
		{name: "id is an integer", row: with(invitationRow(), 0, int64(1))},
		{name: "id is a blob", row: with(invitationRow(), 0, []byte(invitationID))},
		{name: "type is NULL", row: with(invitationRow(), 1, nil)},
		{name: "label is NULL", row: with(invitationRow(), 2, nil)},
		{name: "label is a blob", row: with(invitationRow(), 2, []byte("x"))},
		{name: "num_invites is a float", row: with(invitationRow(), 3, 5.0)},
		{name: "num_invites is text", row: with(invitationRow(), 3, "5")},
		{name: "num_invites is NULL", row: with(invitationRow(), 3, nil)},
		{name: "uses is a float", row: with(invitationRow(), 4, 2.0)},
		{name: "uses is NULL", row: with(invitationRow(), 4, nil)},
		{name: "expires_at is a float", row: with(invitationRow(), 5, 1.8e9)},
		{name: "expires_at is text", row: with(invitationRow(), 5, "soon")},
		{name: "revoked_at is a float", row: with(invitationRow(), 6, 1.7e9)},
		{name: "revoked_at is text", row: with(invitationRow(), 6, "yes")},
		{name: "created_by is an integer", row: with(invitationRow(), 7, int64(1))},
		{name: "created_by is a blob", row: with(invitationRow(), 7, []byte("admin-1"))},
		{name: "created_at is a float", row: with(invitationRow(), 8, 1.7e9)},
		{name: "created_at is NULL", row: with(invitationRow(), 8, nil)},
		{name: "a column too few", row: invitationRow()[:invitationColumns-1]},
		{name: "a column too many", row: append(invitationRow(), "extra")},
		{name: "an empty row", row: row()},
	}

	for _, operation := range invitationOps(t) {
		for _, test := range tests {
			t.Run(operation.name+"/"+test.name, func(t *testing.T) {
				t.Parallel()

				fake := newFake(returning(operation.shape(test.row)))

				got, err := operation.call(fake.store())

				checkErr(t, err, defectOf(operation.rejected))

				if !reflect.DeepEqual(got, store.Invitation{}) {
					t.Errorf("a defective row returned %+v", got)
				}
			})
		}
	}
}

// TestInvitationRowCounts holds how the number of rows a statement returned is
// read: no row is a missing invitation (or, for a create, a defect), and more
// than one is a defect, because every statement names one primary key.
func TestInvitationRowCounts(t *testing.T) {
	t.Parallel()

	for _, operation := range invitationOps(t) {
		if operation.name == "list" {
			continue
		}

		t.Run(operation.name+"/no row", func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning())

			_, err := operation.call(fake.store())

			if operation.notFound {
				if !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("error = %v, want ErrNotFound", err)
				}

				if _, isAPI := errors.AsType[*apierr.Error](err); isAPI {
					t.Errorf("not found %v is classified; the feature must decide that", err)
				}

				return
			}

			checkErr(t, err, defectOf(operation.rejected))

			if errors.Is(err, store.ErrNotFound) {
				t.Errorf("a create that returned no row reports not found: %v", err)
			}
		})

		t.Run(operation.name+"/two rows", func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(operation.shape(invitationRow()), operation.shape(invitationRow())))

			got, err := operation.call(fake.store())

			checkErr(t, err, defectOf(operation.rejected))

			if !reflect.DeepEqual(got, store.Invitation{}) {
				t.Errorf("two rows returned %+v", got)
			}
		})
	}
}

// TestListInvitations holds the list: every row, in the order the database
// returned it, and an empty list that is not nil.
func TestListInvitations(t *testing.T) {
	t.Parallel()

	newer := with(with(invitationRow(), 0, "0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c"), 8, int64(1_700_000_100))
	older := with(invitationRow(), 6, int64(1_700_000_050))

	tests := []struct {
		name string
		rows [][]any
		ids  []string
	}{
		{name: "none", rows: nil, ids: []string{}},
		{name: "an empty result", rows: [][]any{}, ids: []string{}},
		{name: "one", rows: [][]any{invitationRow()}, ids: []string{invitationID}},
		{name: "the order of the database is kept",
			rows: [][]any{newer, older, invitationRow()},
			ids: []string{
				"0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c", invitationID, invitationID,
			}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.rows...))

			got, err := fake.store().ListInvitations(context.Background())
			checkErr(t, err, nil)

			if got == nil {
				t.Fatal("list is nil, want a non-nil slice")
			}

			ids := make([]string, 0, len(got))
			for _, invitation := range got {
				ids = append(ids, invitation.ID)
			}

			if !reflect.DeepEqual(ids, test.ids) {
				t.Errorf("ids = %v, want %v", ids, test.ids)
			}

			// A revoked row stays in the list.
			if len(got) == 3 && got[1].RevokedAt == nil {
				t.Errorf("revoked invitation lost its revocation: %+v", got[1])
			}
		})
	}
}

// TestListInvitationsWithADefectiveRow holds that one bad row fails the whole
// list: a partial list would look like a complete one.
func TestListInvitationsWithADefectiveRow(t *testing.T) {
	t.Parallel()

	fake := newFake(returning(invitationRow(), with(invitationRow(), 3, "five"), invitationRow()))

	got, err := fake.store().ListInvitations(context.Background())

	checkErr(t, err, defectOf(store.CodeInvitationListRejected))

	if got != nil {
		t.Errorf("a defective list returned %+v", got)
	}
}

// withVerdict is the row an update returns: the verdict, then the invitation.
func withVerdict(verdict any, invitation []any) []any {
	return append([]any{verdict}, invitation...)
}

// TestUpdateNumInvitesOutcome holds how the verdict and the row an update
// returned are read: the verdict is the first column, 1 or 0, and the row comes
// back either way, so the feature can say why a change did not apply.
func TestUpdateNumInvitesOutcome(t *testing.T) {
	t.Parallel()

	wantRevoked := wantInvitation()
	wantRevoked.RevokedAt = new(int64(1_700_000_050))

	wantOverCap := wantInvitation()
	wantOverCap.Uses = 7

	wantUpdated := wantInvitation()
	wantUpdated.NumInvites = 9

	tests := []struct {
		name    string
		rows    [][]any
		want    store.Invitation
		applied bool
		missing bool
	}{
		{name: "applied", want: wantUpdated, applied: true,
			rows: [][]any{withVerdict(int64(1), with(invitationRow(), 3, int64(9)))}},
		{name: "not applied: revoked", want: wantRevoked,
			rows: [][]any{withVerdict(int64(0), with(invitationRow(), 6, int64(1_700_000_050)))}},
		{name: "not applied: below the accounts already created", want: wantOverCap,
			rows: [][]any{withVerdict(int64(0), with(invitationRow(), 4, int64(7)))}},
		{name: "no such invitation", rows: nil, missing: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.rows...))

			got, applied, err := fake.store().UpdateNumInvites(
				context.Background(), invID(t), invNum(t, 9))

			if test.missing {
				if !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("error = %v, want ErrNotFound", err)
				}
			} else {
				checkErr(t, err, nil)
			}

			if applied != test.applied {
				t.Errorf("applied = %v, want %v", applied, test.applied)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("invitation = %+v, want %+v", got, test.want)
			}
		})
	}
}

// TestUpdateNumInvitesVerdictDefects holds that a verdict that is not exactly 0
// or 1, or a row that does not lead with one, is a defect: a refusal must not
// be read as an applied change or the other way around.
func TestUpdateNumInvitesVerdictDefects(t *testing.T) {
	t.Parallel()

	updated := with(invitationRow(), 3, int64(9))

	tests := []struct {
		name string
		rows [][]any
	}{
		{name: "verdict is NULL", rows: [][]any{withVerdict(nil, updated)}},
		{name: "verdict is a float", rows: [][]any{withVerdict(1.0, updated)}},
		{name: "verdict is text", rows: [][]any{withVerdict("1", updated)}},
		{name: "verdict is 2", rows: [][]any{withVerdict(int64(2), updated)}},
		{name: "verdict is -1", rows: [][]any{withVerdict(int64(-1), updated)}},
		{name: "the verdict alone", rows: [][]any{row(int64(1))}},
		{name: "no verdict column", rows: [][]any{updated}},
		{name: "two rows", rows: [][]any{withVerdict(int64(1), updated), withVerdict(int64(1), updated)}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.rows...))

			got, applied, err := fake.store().UpdateNumInvites(
				context.Background(), invID(t), invNum(t, 9))

			checkErr(t, err, defectOf(store.CodeInvitationUpdateRejected))

			if applied || !reflect.DeepEqual(got, store.Invitation{}) {
				t.Errorf("a defective result returned %+v, %v", got, applied)
			}
		})
	}
}

// numberedParams is the set of ?N parameters of a query, and whether it also
// has a bare ?, which SQLite numbers after the highest ?N and which would make
// a numbered query ambiguous.
func numberedParams(query string) (map[int]bool, bool) {
	numbers := map[int]bool{}

	for _, match := range regexp.MustCompile(`\?(\d+)`).FindAllStringSubmatch(query, -1) {
		number, _ := strconv.Atoi(match[1])
		numbers[number] = true
	}

	bare := regexp.MustCompile(`\?(\D|$)`).MatchString(query)

	return numbers, bare
}

// checkNumbered asserts that the fake saw exactly one statement with the wanted
// fragments and arguments, and that its numbered parameters are exactly
// ?1 to ?len(args): the number, not the position in the text, says which
// argument a parameter takes, so the arguments are in number order and every
// one is used.
func checkNumbered(t *testing.T, fake *fakeExec, want wantStatement) {
	t.Helper()

	if len(fake.calls) != 1 || len(fake.calls[0]) != 1 {
		t.Fatalf("calls = %d, want one batch of one statement", len(fake.calls))
	}

	statement := fake.calls[0][0]
	query := squash(statement.Query)

	for _, fragment := range want.fragments {
		if !strings.Contains(query, fragment) {
			t.Errorf("statement lacks %q:\n%s", fragment, query)
		}
	}

	if !reflect.DeepEqual(statement.Args, want.args) {
		t.Errorf("args = %#v, want %#v", statement.Args, want.args)
	}

	numbers, bare := numberedParams(query)

	if bare {
		t.Errorf("statement mixes a bare ? with numbered parameters:\n%s", query)
	}

	if len(numbers) != len(statement.Args) {
		t.Errorf("statement has %d distinct parameters for %d args:\n%s", len(numbers), len(statement.Args), query)
	}

	for number := 1; number <= len(statement.Args); number++ {
		if !numbers[number] {
			t.Errorf("parameter ?%d is not used:\n%s", number, query)
		}
	}
}

// TestNumberedParams validates the helper the statement pins rely on.
func TestNumberedParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		query   string
		numbers []int
		bare    bool
	}{
		{name: "numbered, one reused", query: "a = ?2 AND b = ?1 AND c = ?2", numbers: []int{1, 2}, bare: false},
		{name: "bare", query: "a = ? AND b = ?", numbers: nil, bare: true},
		{name: "mixed", query: "a = ?1 AND b = ?", numbers: []int{1}, bare: true},
		{name: "a bare ? at the end", query: "a = ?", numbers: nil, bare: true},
		{name: "none", query: "SELECT 1", numbers: nil, bare: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			numbers, bare := numberedParams(test.query)

			got := make([]int, 0, len(numbers))
			for number := range numbers {
				got = append(got, number)
			}

			if len(got) != len(test.numbers) || bare != test.bare {
				t.Fatalf("numbers = %v bare = %v, want %v %v", got, bare, test.numbers, test.bare)
			}

			for _, number := range test.numbers {
				if !numbers[number] {
					t.Errorf("missing ?%d in %v", number, got)
				}
			}
		})
	}
}

// TestListInvitationsStatement pins the list: every invitation (no filter, so
// revoked ones are included), newest first with the id as the tie-break, and a
// use count that is counted in the statement.
func TestListInvitationsStatement(t *testing.T) {
	t.Parallel()

	fake := newFake(returning())

	_, err := fake.store().ListInvitations(context.Background())
	checkErr(t, err, nil)

	checkStatements(t, fake, wantStatement{
		fragments: []string{
			"FROM invitations i ORDER BY i.created_at DESC, i.id DESC",
			"(SELECT count(*) FROM users u WHERE u.invitation_id = i.id) AS uses",
			"i.expires_at, i.revoked_at, i.created_by, i.created_at",
		},
		args: nil,
	})

	if strings.Contains(squash(fake.calls[0][0].Query), "WHERE i.") {
		t.Error("the list filters invitations; revoked ones must be included")
	}
}

// TestCreateInvitationStatement pins the insert and the arguments in column
// order: an absent expiry is NULL and not zero (zero would be a long-expired
// invitation), and what the caller parsed is what is sent.
func TestCreateInvitationStatement(t *testing.T) {
	t.Parallel()

	manyRunes := strings.Repeat("é", input.MaxInvitationLabelRunes)

	tests := []struct {
		name   string
		change func(*store.NewInvitation)
		args   []any
	}{
		{name: "with an expiry", change: func(*store.NewInvitation) {},
			args: []any{invitationID, invHash(), "member", "workshop", int64(5), now.Unix() + 3600, "admin-1", now.Unix()}},
		{name: "without an expiry is NULL",
			change: func(n *store.NewInvitation) { n.ExpiresAt = nil },
			args:   []any{invitationID, invHash(), "member", "workshop", int64(5), nil, "admin-1", now.Unix()}},
		{name: "an empty label is an empty string and not NULL",
			change: func(n *store.NewInvitation) { n.Label = invLabel(t, "") },
			args:   []any{invitationID, invHash(), "member", "", int64(5), now.Unix() + 3600, "admin-1", now.Unix()}},
		{name: "the longest label, multibyte",
			change: func(n *store.NewInvitation) { n.Label = invLabel(t, manyRunes) },
			args:   []any{invitationID, invHash(), "member", manyRunes, int64(5), now.Unix() + 3600, "admin-1", now.Unix()}},
		{name: "the largest cap",
			change: func(n *store.NewInvitation) { n.NumInvites = invNum(t, input.MaxNumInvites) },
			args: []any{
				invitationID, invHash(), "member", "workshop", int64(input.MaxNumInvites), now.Unix() + 3600,
				"admin-1", now.Unix(),
			}},
		{name: "the smallest cap",
			change: func(n *store.NewInvitation) { n.NumInvites = invNum(t, 1) },
			args:   []any{invitationID, invHash(), "member", "workshop", int64(1), now.Unix() + 3600, "admin-1", now.Unix()}},
		{name: "another type and creator",
			change: func(n *store.NewInvitation) { n.Type, n.CreatedBy = "guest", "admin-2" },
			args:   []any{invitationID, invHash(), "guest", "workshop", int64(5), now.Unix() + 3600, "admin-2", now.Unix()}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(invitationRow()))

			invitation := newInvitation(t)
			test.change(&invitation)

			_, err := fake.store().CreateInvitation(context.Background(), invitation)
			checkErr(t, err, nil)

			checkStatements(t, fake, wantStatement{
				fragments: []string{
					"INSERT INTO invitations (id, code_hash, type, label, num_invites, expires_at, created_by, created_at) " +
						"VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
					"RETURNING id, type, label, num_invites, " +
						"(SELECT count(*) FROM users u WHERE u.invitation_id = invitations.id) AS uses, " +
						"expires_at, revoked_at, created_by, created_at",
				},
				args: test.args,
			})
		})
	}
}

// TestCreateInvitationReturnsTheStoredRow holds that the result is what the
// database returned and not the caller's copy: the response to a create is the
// database's view of the row.
func TestCreateInvitationReturnsTheStoredRow(t *testing.T) {
	t.Parallel()

	stored := row("stored-id", "stored-type", "stored label", int64(77), int64(0), nil, nil, nil, int64(42))
	want := store.Invitation{
		ID: "stored-id", Type: "stored-type", Label: "stored label", NumInvites: 77, Uses: 0,
		ExpiresAt: nil, RevokedAt: nil, CreatedBy: nil, CreatedAt: 42,
	}

	fake := newFake(returning(stored))

	got, err := fake.store().CreateInvitation(context.Background(), newInvitation(t))
	checkErr(t, err, nil)

	if !reflect.DeepEqual(got, want) {
		t.Errorf("invitation = %+v, want %+v", got, want)
	}
}

// TestUpdateNumInvitesStatement pins what makes the update safe: the row is
// matched by id alone, the revoked and cap conditions decide the SET and are
// repeated as the verdict, and the parameters are numbered, so the cap is
// bound twice (?1 the value, ?2 the same value compared with the count).
func TestUpdateNumInvitesStatement(t *testing.T) {
	t.Parallel()

	for _, n := range []int64{1, 5, input.MaxNumInvites} {
		t.Run(strconv.FormatInt(n, 10), func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning())

			_, _, err := fake.store().UpdateNumInvites(context.Background(), invID(t), invNum(t, n))
			if !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("error = %v, want ErrNotFound", err)
			}

			checkNumbered(t, fake, wantStatement{
				fragments: []string{
					"UPDATE invitations SET num_invites = CASE " +
						"WHEN revoked_at IS NULL " +
						"AND (SELECT count(*) FROM users u WHERE u.invitation_id = invitations.id) <= ?2 " +
						"THEN ?1 ELSE num_invites END WHERE id = ?3",
					"RETURNING (revoked_at IS NULL " +
						"AND (SELECT count(*) FROM users u WHERE u.invitation_id = invitations.id) <= ?2) AS applied, " +
						"id, type, label, num_invites, " +
						"(SELECT count(*) FROM users u WHERE u.invitation_id = invitations.id) AS uses, " +
						"expires_at, revoked_at, created_by, created_at",
				},
				args: []any{n, n, invitationID},
			})
		})
	}
}

// TestRevokeInvitationStatement pins the revocation: the earlier time is kept
// (COALESCE), the row is matched by id alone (so "already revoked" and "no such
// invitation" are told apart by the row), and it is never deleted.
func TestRevokeInvitationStatement(t *testing.T) {
	t.Parallel()

	fake := newFake(returning())

	_, err := fake.store().RevokeInvitation(context.Background(), invID(t), now)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}

	checkNumbered(t, fake, wantStatement{
		fragments: []string{
			"UPDATE invitations SET revoked_at = COALESCE(revoked_at, ?1) WHERE id = ?2",
			"RETURNING id, type, label, num_invites, " +
				"(SELECT count(*) FROM users u WHERE u.invitation_id = invitations.id) AS uses, " +
				"expires_at, revoked_at, created_by, created_at",
		},
		args: []any{now.Unix(), invitationID},
	})
}

// TestRevokeInvitationReturnsTheRowAsLeft holds that a revoke of an invitation
// that was already revoked is the same answer as a first revoke: the row, with
// whichever time the write left.
func TestRevokeInvitationReturnsTheRowAsLeft(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		row  []any
		at   int64
	}{
		{name: "revoked now", row: with(invitationRow(), 6, now.Unix()), at: now.Unix()},
		{name: "already revoked earlier keeps the earlier time",
			row: with(invitationRow(), 6, int64(1_600_000_000)), at: 1_600_000_000},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(returning(test.row))

			got, err := fake.store().RevokeInvitation(context.Background(), invID(t), now)
			checkErr(t, err, nil)

			if got.RevokedAt == nil || *got.RevokedAt != test.at {
				t.Errorf("RevokedAt = %v, want %d", got.RevokedAt, test.at)
			}
		})
	}
}

// TestInvitationQueriesNeverReturnTheCode holds that no statement can return
// the code's hash: a code is shown once, in the response that created it.
func TestInvitationQueriesNeverReturnTheCode(t *testing.T) {
	t.Parallel()

	queries := packageQueries(t)

	for _, name := range []string{
		"listInvitationsQuery", "insertInvitationQuery",
		"updateNumInvitesQuery", "revokeInvitationQuery",
	} {
		query, ok := queries[name]
		if !ok {
			t.Fatalf("query %s was not found", name)
		}

		lists := columnLists(query)
		if len(lists) == 0 {
			t.Errorf("%s returns no columns", name)
		}

		for _, list := range lists {
			if strings.Contains(list, "code") {
				t.Errorf("%s returns %q", name, list)
			}
		}
	}
}

// TestInvitationFailures holds how a failed or malformed batch is reported by
// each operation. The writes' constraint failures differ from the reads', so
// they have their own tests below.
func TestInvitationFailures(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	id := invID(t)

	tests := []struct {
		name             string
		failed, rejected string
		run              func(*store.Store) error
	}{
		{name: "list", failed: store.CodeInvitationListFailed, rejected: store.CodeInvitationListRejected,
			run: func(s *store.Store) error { return lastErr(s.ListInvitations(ctx)) }},
		{name: "update", failed: store.CodeInvitationUpdateFailed, rejected: store.CodeInvitationUpdateRejected,
			run: func(s *store.Store) error { return lastErr2(s.UpdateNumInvites(ctx, id, invNum(t, 3))) }},
		{name: "revoke", failed: store.CodeInvitationRevokeFailed, rejected: store.CodeInvitationRevokeRejected,
			run: func(s *store.Store) error { return lastErr(s.RevokeInvitation(ctx, id, now)) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			runFailures(t, 1, test.failed, test.rejected, invitationsDescription, test.run)
		})
	}
}

// invitationsDescription is the client-safe text of an Unavailable failure.
const invitationsDescription = "invitations are temporarily unavailable"

// TestCreateInvitationFailures holds how a failed or malformed batch is
// reported. A UNIQUE collision (the id and the code hash are both generated by
// the server) and a NOT NULL failure are not the client's to resolve, so unlike
// other creates they are defects and not conflicts.
func TestCreateInvitationFailures(t *testing.T) {
	t.Parallel()

	for _, f := range infraFailures(1, store.CodeInvitationCreateFailed, store.CodeInvitationCreateRejected,
		invitationsDescription) {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()

			fake := newFake(f.outcome)

			_, err := fake.store().CreateInvitation(context.Background(), newInvitation(t))

			if f.conflict {
				// A defect, not a conflict. Its text is kept for the log, but the
				// sentinel is not in the chain, so a feature that matches on it
				// cannot mistake this for the client's doing.
				checkErr(t, err, defectOf(store.CodeInvitationCreateRejected))

				if !strings.Contains(err.Error(), f.outcome.err.Error()) {
					t.Errorf("error %v lost the database's text %v", err, f.outcome.err)
				}
			} else {
				checkFailure(t, err, f)
			}

			if errors.Is(err, store.ErrConflict) {
				t.Errorf("a create reports a conflict: %v", err)
			}

			if len(fake.calls) != 1 {
				t.Errorf("exec called %d times, want 1", len(fake.calls))
			}
		})
	}
}

// TestInvitationCodes pins the wire codes the operations report. Clients and
// dashboards match on them, so they change only deliberately.
func TestInvitationCodes(t *testing.T) {
	t.Parallel()

	tests := []struct{ got, want string }{
		{store.CodeInvitationListFailed, "invitation_list_failed"},
		{store.CodeInvitationListRejected, "invitation_list_rejected"},
		{store.CodeInvitationCreateFailed, "invitation_create_failed"},
		{store.CodeInvitationCreateRejected, "invitation_create_rejected"},
		{store.CodeInvitationUpdateFailed, "invitation_update_failed"},
		{store.CodeInvitationUpdateRejected, "invitation_update_rejected"},
		{store.CodeInvitationRevokeFailed, "invitation_revoke_failed"},
		{store.CodeInvitationRevokeRejected, "invitation_revoke_rejected"},
	}

	for _, test := range tests {
		if test.got != test.want {
			t.Errorf("code %q, want %q", test.got, test.want)
		}
	}
}
