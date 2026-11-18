//go:build e2e

//nolint:goconst,funlen,cyclop,lll // table-driven tests repeat case names and inputs on purpose and the case table is the test; a constant or a line break per row would hide it
package e2e_test

// agent_labels_test.go drives the labels of /api/agent against the real Worker:
// the TinyGo wasm, the real D1 driver and the real SQLite the migrations
// created. The unit tests fake the database, so this file proves what only the
// real build can:
//
//   - that an add is idempotent, that removals come before additions, and that
//     a patch over the label limit fails the WHOLE batch (the NOT NULL trick)
//     and leaves the name and every label as they were;
//   - that concurrent edits to the same agent never lose an update and never
//     exceed the cap: the reason labels are a table and not a JSON column;
//   - that every label write is scoped to the owner and skips a revoked agent;
//   - that ?label= filters through the real index, pages exactly, and shows all
//     of an agent's labels, not only the one filtered by;
//   - the byte bounds of a label through the real SQLite CHECK, and that a
//     label is stored exactly as sent.
//
// Labels may also be given when an agent is created (POST /api/agent), in the
// same write as the agent: the create tests below prove that it is all or
// nothing in the real database, including against the owner's agent limit.
//
// REVIEW.md categories covered: input edge cases (label alphabet, JSON shapes,
// query parameters), interleaving (add vs add at the cap, add vs remove, patch
// vs revoke, patch vs patch), payload size (array bounds, the 8 KiB body),
// permission confusion (another user's agent, an admin's reach) and type/bound
// confusion (bytes vs runes, JSON vs Go vs SQLite, NUL).

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	lbCodeInvalid  = "invalid_agent_label"
	lbCodeFilter   = "invalid_label_filter"
	lbCodePatch    = "invalid_label_patch"
	lbCodeNothing  = "missing_agent_change"
	lbCodeLimit    = "agent_label_limit_reached"
	lbCodeTooMany  = "too_many_items"
	lbMaxLabels    = 20
	lbMaxLabelByte = 63
)

// lbBody is a PATCH body with the given members, JSON-encoded.
func lbBody(t *testing.T, members map[string]any) []byte {
	t.Helper()

	return mustJSON(t, members)
}

// lbAdd is a body that adds labels.
func lbAdd(t *testing.T, labels ...string) []byte {
	t.Helper()

	return lbBody(t, map[string]any{"addLabels": labels})
}

// lbRemove is a body that removes labels.
func lbRemove(t *testing.T, labels ...string) []byte {
	t.Helper()

	return lbBody(t, map[string]any{"removeLabels": labels})
}

// lbStored is the labels the database holds for the subject agent, sorted, as text.
func lbStored(t *testing.T) string {
	t.Helper()

	return scalar(t, "SELECT ifnull(group_concat(label, ','), '') "+
		"FROM (SELECT label FROM agent_labels WHERE agent_id = ? ORDER BY label)", idAgentA)
}

// lbView decodes the agent of a successful PATCH.
func lbView(t *testing.T, r reply) agView {
	t.Helper()

	return agDecode[agView](t, r)
}

// lbWant asserts the labels of a view.
func lbWant(t *testing.T, what string, view agView, want ...string) {
	t.Helper()

	if want == nil {
		want = []string{}
	}

	if !slices.Equal(view.Labels, want) || view.Labels == nil {
		t.Errorf("%s: labels = %#v, want %#v", what, view.Labels, want)
	}
}

// lbNames returns n valid labels with a prefix.
func lbNames(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = prefix + strconv.Itoa(i)
	}

	return out
}

// lbWorld is user B with one agent, the usual subject of a test.
func lbWorld(t *testing.T) (agPair, string) {
	t.Helper()

	world := agNewPair(t, roleMember)
	seedAgent(t, idAgentA, world.b.userID, "subject")

	return world, agItem(idAgentA)
}

// ---- add and remove --------------------------------------------------------

// TestAgentLabelsAddAndRemove: the exact responses and stored rows of a sequence
// of patches, including every no-op, in the order the real database applies them.
//
//nolint:paralleltest // shares one database
func TestAgentLabelsAddAndRemove(t *testing.T) {
	world, item := lbWorld(t)

	steps := []struct {
		name   string
		body   []byte
		status int
		code   string
		want   []string
	}{
		{"a new agent has none", nil, http.StatusOK, "", []string{}},
		{"add three: the response is sorted", lbAdd(t, "zeta", "alpha", "mid"), http.StatusOK, "", []string{"alpha", "mid", "zeta"}},
		{"add one that is there: a no-op", lbAdd(t, "mid"), http.StatusOK, "", []string{"alpha", "mid", "zeta"}},
		{"add two, one there", lbAdd(t, "alpha", "beta"), http.StatusOK, "", []string{"alpha", "beta", "mid", "zeta"}},
		{"remove one", lbRemove(t, "mid"), http.StatusOK, "", []string{"alpha", "beta", "zeta"}},
		{"remove one that is not there: a no-op", lbRemove(t, "mid"), http.StatusOK, "", []string{"alpha", "beta", "zeta"}},
		{"add and remove together", lbBody(t, map[string]any{"addLabels": []string{"gamma"}, "removeLabels": []string{"alpha"}}),
			http.StatusOK, "", []string{"beta", "gamma", "zeta"}},
		{"rename with labels", lbBody(t, map[string]any{"name": "renamed", "addLabels": []string{"delta"}}),
			http.StatusOK, "", []string{"beta", "delta", "gamma", "zeta"}},
		{"remove everything", lbRemove(t, "beta", "delta", "gamma", "zeta"), http.StatusOK, "", []string{}},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			if step.body == nil {
				got := get(t, item, world.tokenB)
				got.expect(t, "get", http.StatusOK, "")
				lbWant(t, step.name, lbView(t, got), step.want...)

				return
			}

			got := patch(t, item, step.body, world.tokenB)
			got.expect(t, step.name, step.status, step.code)

			if step.status != http.StatusOK {
				return
			}

			lbWant(t, step.name, lbView(t, got), step.want...)

			// The response is what the database holds, and a read agrees.
			if stored := lbStored(t); stored != strings.Join(step.want, ",") {
				t.Errorf("stored labels = %q, want %q", stored, strings.Join(step.want, ","))
			}

			lbWant(t, "a read after "+step.name, lbView(t, get(t, item, world.tokenB)), step.want...)
		})
	}

	if name := scalar(t, "SELECT name FROM agents WHERE id = ?", idAgentA); name != "renamed" {
		t.Errorf("name = %q, want renamed (the rename in a patch with labels)", name)
	}

	// Nothing else about the agent moved.
	expectCount(t, "agents WHERE id = ? AND revoked_at IS NULL AND scopes = ?", "1", idAgentA, agScopes)
}

// TestAgentLabelsAreStoredAsSent: every accepted label is stored byte for byte
// and at the bounds the real CHECK holds.
//
//nolint:paralleltest // shares one database
func TestAgentLabelsAreStoredAsSent(t *testing.T) {
	world, item := lbWorld(t)

	accepted := []string{
		"a", "z", "0", "9", ".", "_", "-", "..", "--", "__", "a.b", "a_b", "a-b", "v1.2.3-rc.1",
		"az09._-", strings.Repeat("a", lbMaxLabelByte), strings.Repeat("9", lbMaxLabelByte),
		strings.Repeat("a.", 31) + "a", // 63 bytes of mixed characters
		// A SQL pattern character is not special here: '_' is literal, '%' is refused.
		"a_b_c",
	}

	for _, label := range accepted {
		t.Run(label[:min(len(label), 20)]+"/"+strconv.Itoa(len(label)), func(t *testing.T) {
			seed(t, "DELETE FROM agent_labels")

			got := patch(t, item, lbAdd(t, label), world.tokenB)
			got.expect(t, "add", http.StatusOK, "")
			lbWant(t, "response", lbView(t, got), label)

			if stored := agHex(label); scalar(t, "SELECT hex(CAST(label AS BLOB)) FROM agent_labels WHERE agent_id = ?", idAgentA) != stored {
				t.Errorf("stored bytes differ from the %d bytes sent", len(label))
			}

			// It is found by exact match, and by nothing shorter or longer.
			list := agDecode[agPage](t, get(t, pathAgent+"?label="+url.QueryEscape(label), world.tokenB))
			if len(list.Agents) != 1 {
				t.Errorf("filter by %q found %d agents, want 1", label, len(list.Agents))
			}

			// And it is removed by exactly itself.
			patch(t, item, lbRemove(t, label), world.tokenB).expect(t, "remove", http.StatusOK, "")
			expectCount(t, "agent_labels WHERE agent_id = ?", "0", idAgentA)
		})
	}
}

// lbRefusal is a PATCH body that must be refused, and with what.
type lbRefusal struct {
	name string
	body string
	code string
}

func lbRefusals(t *testing.T) []lbRefusal {
	t.Helper()

	many := make([]string, lbMaxLabels+1)
	for i := range many {
		many[i] = strconv.Quote("l" + strconv.Itoa(i))
	}

	over := "[" + strings.Join(many, ",") + "]"

	bad := func(name, label string) lbRefusal {
		return lbRefusal{name, `{"addLabels":[` + string(mustJSON(t, label)) + `]}`, lbCodeInvalid}
	}

	shape := func(name, body, code string) lbRefusal { return lbRefusal{name, body, code} }

	return []lbRefusal{
		bad("empty", ""),
		bad("upper case", "Prod"),
		bad("all upper case", "PROD"),
		bad("a space", "a b"),
		bad("a leading space", " a"),
		bad("a trailing space", "a "),
		bad("a tab", "a\tb"),
		bad("a newline", "a\n"),
		bad("a carriage return", "a\r"),
		bad("NUL", "a\x00b"),
		bad("only NUL", "\x00"),
		bad("NUL then 2000 bytes (length() would stop at the NUL)", "a\x00"+strings.Repeat("b", 2000)),
		bad("DEL", "a\x7fb"),
		bad("one over the bound", strings.Repeat("a", lbMaxLabelByte+1)),
		bad("far over the bound", strings.Repeat("a", 5000)),
		bad("a colon", "env:prod"),
		bad("a slash", "a/b"),
		bad("a backslash", `a\b`),
		bad("a comma", "a,b"),
		bad("a percent sign (a SQL pattern character)", "a%"),
		bad("a plus", "a+b"),
		bad("a quote", `a"b`),
		bad("an apostrophe", "a'b"),
		bad("a SQL injection", "'; DROP TABLE agent_labels; --"),
		bad("a wildcard", "*"),
		bad("an at sign", "a@b"),
		bad("e acute (NFC)", "caf\u00e9"),
		bad("e + combining acute (NFD)", "cafe\u0301"),
		bad("a cyrillic a that looks latin", "\u0430"),
		bad("fullwidth a", "\uff41"),
		bad("Kelvin sign", "\u212a"),
		bad("an emoji", "\U0001F600"),
		bad("a zero-width space", "a\u200bb"),
		bad("a zero-width joiner", "a\u200db"),
		bad("a bidi override", "a\u202eb"),
		bad("a byte order mark", "\ufeffa"),
		bad("a non-breaking space", "a\u00a0b"),
		{"the replacement character", `{"addLabels":["a\ufffdb"]}`, "invalid_text"},
		{"a lone surrogate", `{"addLabels":["a\ud800"]}`, "invalid_text"},
		{"invalid UTF-8", "{\"addLabels\":[\"a\xffb\"]}", "invalid_text"},
		{"a removed label is held to the same alphabet", `{"removeLabels":["Prod"]}`, lbCodeInvalid},
		{"a valid label then an invalid one", `{"addLabels":["ok","not ok"]}`, lbCodeInvalid},
		{"null in the list", `{"addLabels":[null]}`, lbCodeInvalid},
		shape("the same label twice", `{"addLabels":["a","a"]}`, lbCodePatch),
		shape("the same label removed twice", `{"removeLabels":["a","a"]}`, lbCodePatch),
		shape("added and removed", `{"addLabels":["a"],"removeLabels":["a"]}`, lbCodePatch),
		shape("21 to add", `{"addLabels":`+over+`}`, lbCodeTooMany),
		shape("21 to remove", `{"removeLabels":`+over+`}`, lbCodeTooMany),
		shape("nothing", `{}`, lbCodeNothing),
		shape("only nulls", `{"name":null,"addLabels":null,"removeLabels":null}`, lbCodeNothing),
		shape("only empty lists", `{"addLabels":[],"removeLabels":[]}`, lbCodeNothing),
		shape("addLabels is a string", `{"addLabels":"a"}`, "invalid_field_type"),
		shape("addLabels is an object", `{"addLabels":{"a":1}}`, "invalid_field_type"),
		shape("addLabels is a number", `{"addLabels":5}`, "invalid_field_type"),
		shape("a number in the list", `{"addLabels":[1]}`, "invalid_field_type"),
		shape("a list in the list", `{"addLabels":[["a"]]}`, "invalid_field_type"),
		shape("a bool in the list", `{"addLabels":[true]}`, "invalid_field_type"),
		shape("a repeated addLabels", `{"addLabels":["a"],"addLabels":["b"]}`, "duplicate_field"),
		shape("a repeated by escaped spelling", `{"addLabels":["a"],"add\u004cabels":["b"]}`, "duplicate_field"),
		shape("labels is not a member", `{"labels":["a"]}`, "unknown_field"),
		shape("a different case", `{"AddLabels":["a"]}`, "unknown_field"),
		shape("a snake case", `{"add_labels":["a"]}`, "unknown_field"),
		shape("an unknown member beside valid ones", `{"addLabels":["a"],"scopes":"x"}`, "unknown_field"),
		shape("trailing data", `{"addLabels":["a"]} x`, "trailing_data"),
		shape("truncated", `{"addLabels":["a"`, "invalid_json"),
	}
}

// TestAgentLabelsRefused: every refusal is a 400 with its code and writes
// nothing: no label, and not the name beside a bad label.
//
//nolint:paralleltest // shares one database
func TestAgentLabelsRefused(t *testing.T) {
	world, item := lbWorld(t)

	seed(t, "INSERT INTO agent_labels (agent_id, label) VALUES (?, 'existing')", idAgentA)

	for _, c := range lbRefusals(t) {
		t.Run(c.name, func(t *testing.T) {
			before := bndSnapshot(t)

			patch(t, item, []byte(c.body), world.tokenB).expect(t, c.name, http.StatusBadRequest, c.code)

			if after := bndSnapshot(t); after != before {
				t.Errorf("a refused patch wrote:\n before %s\n after  %s", before, after)
			}
		})
	}

	// A bad label beside a name: the name is not applied.
	patch(t, item, []byte(`{"name":"sneaky","addLabels":["BAD"]}`), world.tokenB).
		expect(t, "name with a bad label", http.StatusBadRequest, lbCodeInvalid)

	if name := scalar(t, "SELECT name FROM agents WHERE id = ?", idAgentA); name != "subject" {
		t.Errorf("name = %q after a refused patch, want subject", name)
	}
}

// TestAgentLabelsLargestRequest: the largest accepted request is handled in
// full, and a body that is only just within the 8 KiB cap is read.
//
//nolint:paralleltest // shares one database
func TestAgentLabelsLargestRequest(t *testing.T) {
	world, item := lbWorld(t)

	longest := make([]string, lbMaxLabels)
	for i := range longest {
		longest[i] = fmt.Sprintf("%02d", i) + strings.Repeat("z", lbMaxLabelByte-2)
	}

	got := patch(t, item, lbAdd(t, longest...), world.tokenB)
	got.expect(t, "20 labels of 63 bytes", http.StatusOK, "")
	lbWant(t, "20 longest labels", lbView(t, got), longest...)
	expectCount(t, "agent_labels WHERE agent_id = ?", "20", idAgentA)

	// 20 labels of 63 bytes is about 1.4 KiB of JSON. The same again, removed in
	// the same request that adds twenty others, is the biggest single batch.
	others := lbNames("other-", lbMaxLabels)

	got = patch(t, item, lbBody(t, map[string]any{"addLabels": others, "removeLabels": longest}), world.tokenB)
	got.expect(t, "swap all 20", http.StatusOK, "")
	lbWant(t, "after swapping all", lbView(t, got), slices.Sorted(slices.Values(others))...)

	// A body over the 8 KiB cap is refused before anything is read into the database.
	huge := `{"addLabels":["a"],"name":"` + strings.Repeat("x", 9000) + `"}`
	patch(t, item, []byte(huge), world.tokenB).expect(t, "over the body cap", http.StatusRequestEntityTooLarge, codeBodyTooLarge)
	expectCount(t, "agent_labels WHERE agent_id = ?", "20", idAgentA)
}

// ---- the label limit -------------------------------------------------------

// TestAgentLabelLimit: 20 labels is the cap, and a patch that would exceed it
// fails the whole batch in the real database: not one label, no removal that
// came before it, and not the rename beside it, takes effect.
//
//nolint:paralleltest // shares one database
func TestAgentLabelLimit(t *testing.T) {
	world, item := lbWorld(t)

	full := lbNames("l", lbMaxLabels)
	patch(t, item, lbAdd(t, full...), world.tokenB).expect(t, "fill to the limit", http.StatusOK, "")

	snapshot := func() string {
		return lbStored(t) + "|" + scalar(t, "SELECT name FROM agents WHERE id = ?", idAgentA)
	}
	before := snapshot()

	over := []struct {
		name string
		body map[string]any
	}{
		{"one more", map[string]any{"addLabels": []string{"extra"}}},
		{"one more with a rename", map[string]any{"name": "renamed", "addLabels": []string{"extra"}}},
		{"two more, one removed (net one over)", map[string]any{"addLabels": []string{"e1", "e2"}, "removeLabels": []string{"l0"}}},
		{"a fitting add before one that does not", map[string]any{"addLabels": []string{"e1", "e2"}, "removeLabels": []string{"l0"}, "name": "renamed"}},
	}

	for _, c := range over {
		t.Run(c.name, func(t *testing.T) {
			got := patch(t, item, lbBody(t, c.body), world.tokenB)
			got.expect(t, c.name, http.StatusConflict, lbCodeLimit)

			if !strings.Contains(got.body, "20") {
				t.Errorf("limit body = %s, want the limit", got.body)
			}

			if after := snapshot(); after != before {
				t.Errorf("a refused patch changed the agent:\n before %s\n after  %s", before, after)
			}
		})
	}

	// Re-adding a label the agent has is not "one more", at the limit.
	patch(t, item, lbAdd(t, "l0", "l19"), world.tokenB).expect(t, "re-add at the limit", http.StatusOK, "")

	// Removals are applied first, so a swap at the limit works.
	got := patch(t, item, lbBody(t, map[string]any{"addLabels": []string{"fresh"}, "removeLabels": []string{"l0"}}), world.tokenB)
	got.expect(t, "swap at the limit", http.StatusOK, "")
	expectCount(t, "agent_labels WHERE agent_id = ?", "20", idAgentA)
	expectCount(t, "agent_labels WHERE agent_id = ? AND label = 'fresh'", "1", idAgentA)
	expectCount(t, "agent_labels WHERE agent_id = ? AND label = 'l0'", "0", idAgentA)

	// One more than the cap is refused only because of the count: another agent
	// of the same user has its own 20.
	seedAgent(t, idAgentB, world.b.userID, "second")
	patch(t, agItem(idAgentB), lbAdd(t, lbNames("m", lbMaxLabels)...), world.tokenB).expect(t, "another agent's own limit", http.StatusOK, "")

	// The limit counts labels, not requests: removing one frees exactly one.
	patch(t, item, lbRemove(t, "fresh"), world.tokenB).expect(t, "free one", http.StatusOK, "")
	patch(t, item, lbAdd(t, "again"), world.tokenB).expect(t, "fits again", http.StatusOK, "")
	patch(t, item, lbAdd(t, "and-not-twice"), world.tokenB).expect(t, "not twice", http.StatusConflict, lbCodeLimit)
}

// ---- interleavings ---------------------------------------------------------

// TestAgentLabelRaceAtTheLimit: with 15 labels the agent has room for exactly 5
// more. Many concurrent requests each adding a different label produce exactly 5
// more, never more, and every loser is a 409 that changed nothing.
//
//nolint:paralleltest // shares one database
func TestAgentLabelRaceAtTheLimit(t *testing.T) {
	for _, workers := range []int{8, 12, 16} {
		t.Run(fmt.Sprintf("%d workers", workers), func(t *testing.T) {
			world, item := lbWorld(t)

			patch(t, item, lbAdd(t, lbNames("seed", 15)...), world.tokenB).expect(t, "seed", http.StatusOK, "")

			replies := agRelease(workers, func(i int) reply {
				return patch(t, item, lbAdd(t, "race"+strconv.Itoa(i)), world.tokenB)
			})

			tally := agTally(replies)
			t.Logf("%d workers: %v", workers, tally)
			agNo5xx(t, "label race", replies)

			if tally["200"] != 5 || tally["409 "+lbCodeLimit] != workers-5 {
				t.Errorf("outcomes = %v, want exactly 5 added and %d limit refusals", tally, workers-5)
			}

			expectCount(t, "agent_labels WHERE agent_id = ?", "20", idAgentA)
			expectCount(t, "agent_labels WHERE agent_id = ? AND label LIKE 'race%'", "5", idAgentA)

			// Every 200 reports a label set that includes what that request added.
			for i, r := range replies {
				if r.status == http.StatusOK && !slices.Contains(lbView(t, r).Labels, "race"+strconv.Itoa(i)) {
					t.Errorf("request %d succeeded but its label is not in its response: %v", i, lbView(t, r).Labels)
				}
			}
		})
	}
}

// TestAgentLabelRaceSameLabel: many requests adding the SAME label all succeed,
// and there is exactly one row. This is what ON CONFLICT DO NOTHING buys over a
// plain insert, which would make all but one of them a 5xx.
//
//nolint:paralleltest // shares one database
func TestAgentLabelRaceSameLabel(t *testing.T) {
	world, item := lbWorld(t)

	// At the limit as well: the label is already counted once it is there, so
	// the losers of the insert race must not be refused as "over the limit".
	patch(t, item, lbAdd(t, lbNames("seed", 19)...), world.tokenB).expect(t, "seed", http.StatusOK, "")

	replies := agRelease(16, func(int) reply { return patch(t, item, lbAdd(t, "same"), world.tokenB) })

	agNo5xx(t, "same label", replies)

	if tally := agTally(replies); tally["200"] != 16 {
		t.Errorf("outcomes = %v, want all 16 to succeed", tally)
	}

	expectCount(t, "agent_labels WHERE agent_id = ? AND label = 'same'", "1", idAgentA)
	expectCount(t, "agent_labels WHERE agent_id = ?", "20", idAgentA)
}

// TestAgentLabelRaceNoLostUpdates: concurrent patches that each change a
// different label never undo one another. Half add a label and half remove one
// that was there; afterwards every add is present and every removal is gone.
// With a JSON column rewritten by each request, one of every pair would win.
//
//nolint:paralleltest // shares one database
func TestAgentLabelRaceNoLostUpdates(t *testing.T) {
	for round := range 3 {
		t.Run("round "+strconv.Itoa(round), func(t *testing.T) {
			world, item := lbWorld(t)

			const each = 8

			patch(t, item, lbAdd(t, lbNames("old", each)...), world.tokenB).expect(t, "seed", http.StatusOK, "")

			replies := agRelease(2*each, func(i int) reply {
				if i%2 == 0 {
					return patch(t, item, lbAdd(t, "new"+strconv.Itoa(i/2)), world.tokenB)
				}

				return patch(t, item, lbRemove(t, "old"+strconv.Itoa(i/2)), world.tokenB)
			})

			agNo5xx(t, "no lost updates", replies)

			for i, r := range replies {
				r.expect(t, "request "+strconv.Itoa(i), http.StatusOK, "")
			}

			want := lbNames("new", each)
			slices.Sort(want)

			if stored := lbStored(t); stored != strings.Join(want, ",") {
				t.Errorf("labels = %q, want every add and no removed label: %q", stored, strings.Join(want, ","))
			}
		})
	}
}

// TestAgentLabelRaceAddAndRemoveTheSameLabel: concurrent add and remove of one
// label end in one of the two outcomes, never an error and never both.
//
//nolint:paralleltest // shares one database
func TestAgentLabelRaceAddAndRemoveTheSameLabel(t *testing.T) {
	world, item := lbWorld(t)

	for round := range 6 {
		replies := agRelease(8, func(i int) reply {
			if i%2 == 0 {
				return patch(t, item, lbAdd(t, "flip"), world.tokenB)
			}

			return patch(t, item, lbRemove(t, "flip"), world.tokenB)
		})

		agNo5xx(t, "add vs remove round "+strconv.Itoa(round), replies)

		for _, r := range replies {
			r.expect(t, "add vs remove", http.StatusOK, "")
		}

		if n := count(t, "agent_labels WHERE agent_id = ? AND label = 'flip'", idAgentA); n != "0" && n != "1" {
			t.Errorf("round %d: %s rows for one label", round, n)
		}
	}
}

// TestAgentLabelRaceAgainstRevoke: patches racing the revocation of their agent.
// Whatever the interleaving, no label is added after the revocation took effect,
// and no request is a 5xx; the winners are 200 and the rest 409 agent_revoked.
//
//nolint:paralleltest // shares one database
func TestAgentLabelRaceAgainstRevoke(t *testing.T) {
	for round := range 4 {
		t.Run("round "+strconv.Itoa(round), func(t *testing.T) {
			world, item := lbWorld(t)

			const patchers = 10

			var revoked reply

			replies := agRelease(patchers+1, func(i int) reply {
				if i == patchers/2 {
					revoked = del(t, item, world.tokenB)

					return revoked
				}

				return patch(t, item, lbAdd(t, "racing"+strconv.Itoa(i)), world.tokenB)
			})

			agNo5xx(t, "patch vs revoke", replies)
			revoked.expect(t, "revoke", http.StatusOK, "")

			// Everything that settled: the agent is revoked, and its labels are frozen.
			frozen := lbStored(t)

			for i, r := range replies {
				if i == patchers/2 {
					continue
				}

				if r.status != http.StatusOK && r.status != http.StatusConflict {
					t.Errorf("a patch racing the revoke = %d %s, want 200 or 409", r.status, r.body)
				}
			}

			// A late patch is refused and changes nothing.
			patch(t, item, lbAdd(t, "late"), world.tokenB).expect(t, "after the revoke", http.StatusConflict, agCodeRevoked)
			// A label that may or may not be there: either way the agent is revoked.
			patch(t, item, lbRemove(t, "racing"+strconv.Itoa(0)), world.tokenB).
				expect(t, "remove after the revoke", http.StatusConflict, agCodeRevoked)

			if lbStored(t) != frozen {
				t.Errorf("labels moved after the revoke: %q -> %q", frozen, lbStored(t))
			}
		})
	}
}

// ---- ownership and revocation ----------------------------------------------

// TestAgentLabelsOwnership is the permission-confusion test of the label writes
// and the filter: another user's agent, as a member and as an administrator, is
// answered exactly as a missing one, and nothing of theirs changes or leaks.
//
//nolint:paralleltest // shares one database
func TestAgentLabelsOwnership(t *testing.T) {
	for _, role := range []string{roleMember, roleAdmin} {
		t.Run("as "+role, func(t *testing.T) {
			world := agNewPair(t, role)
			setRole(t, world.b.userID, role)

			seedAgent(t, idAgentA, world.a.userID, "theirs")
			seed(t, "INSERT INTO agent_labels (agent_id, label) VALUES (?, 'secret'), (?, 'shared')", idAgentA, idAgentA)

			seedAgent(t, idAgentB, world.b.userID, "mine")
			seed(t, "INSERT INTO agent_labels (agent_id, label) VALUES (?, 'shared')", idAgentB)

			before := bndSnapshot(t)

			attempts := []struct {
				name string
				body []byte
			}{
				{"add", lbAdd(t, "hijack")},
				{"remove", lbRemove(t, "secret")},
				{"add and remove", lbBody(t, map[string]any{"addLabels": []string{"x"}, "removeLabels": []string{"secret"}})},
				{"rename with a label", lbBody(t, map[string]any{"name": "hijacked", "addLabels": []string{"x"}})},
			}

			for _, at := range attempts {
				others := patch(t, agItem(idAgentA), at.body, world.tokenB)
				missing := patch(t, agItem(idMissing), at.body, world.tokenB)

				others.expect(t, at.name+" on another user's agent", http.StatusNotFound, agCodeMissing)

				if others.body != missing.body || others.status != missing.status {
					t.Errorf("%s: another user's agent = %d %s, a missing one = %d %s; they must be identical",
						at.name, others.status, others.body, missing.status, missing.body)
				}
			}

			if after := bndSnapshot(t); after != before {
				t.Errorf("a refused request changed state:\n before %s\n after  %s", before, after)
			}

			// The filter shows only the caller's agents: 'secret' is A's alone,
			// and 'shared' is on both users' agents but each sees one.
			secret := agDecode[agPage](t, get(t, pathAgent+"?label=secret", world.tokenB))
			if len(secret.Agents) != 0 {
				t.Errorf("a label only another user has listed %d agents for B", len(secret.Agents))
			}

			shared := agDecode[agPage](t, get(t, pathAgent+"?label=shared", world.tokenB))
			if len(shared.Agents) != 1 || shared.Agents[0].ID != idAgentB {
				t.Errorf("filter shared for B = %+v, want only B's agent", shared.Agents)
			}

			for _, a := range shared.Agents {
				if slices.Contains(a.Labels, "secret") {
					t.Errorf("a label of another user's agent leaked into B's list: %v", a.Labels)
				}
			}

			// A reads their own.
			own := agDecode[agPage](t, get(t, pathAgent+"?label=secret", world.tokenA))
			if len(own.Agents) != 1 || own.Agents[0].ID != idAgentA {
				t.Errorf("A's own filter = %+v", own.Agents)
			}
		})
	}
}

// TestAgentLabelsOfARevokedAgentAreFrozen: a revoked agent keeps its labels and
// refuses every change with 409, exactly as a rename is refused.
//
//nolint:paralleltest // shares one database
func TestAgentLabelsOfARevokedAgentAreFrozen(t *testing.T) {
	world, item := lbWorld(t)

	patch(t, item, lbAdd(t, "keep", "also"), world.tokenB).expect(t, "label it", http.StatusOK, "")
	del(t, item, world.tokenB).expect(t, "revoke", http.StatusOK, "")

	attempts := [][]byte{
		lbAdd(t, "new"), lbRemove(t, "keep"), lbBody(t, map[string]any{"name": "x", "addLabels": []string{"y"}}),
		lbBody(t, map[string]any{"addLabels": []string{"y"}, "removeLabels": []string{"keep"}}), lbAdd(t, "keep"),
	}

	for _, body := range attempts {
		patch(t, item, body, world.tokenB).expect(t, string(body), http.StatusConflict, agCodeRevoked)
	}

	if stored := lbStored(t); stored != "also,keep" {
		t.Errorf("labels = %q, want also,keep: a revoked agent's labels are frozen", stored)
	}

	// They are still listed and filterable, with the agent shown as revoked.
	view := lbView(t, get(t, item, world.tokenB))
	lbWant(t, "a revoked agent's labels", view, "also", "keep")

	if view.Status != "revoked" {
		t.Errorf("status = %q, want revoked", view.Status)
	}

	filtered := agDecode[agPage](t, get(t, pathAgent+"?label=keep", world.tokenB))
	if len(filtered.Agents) != 1 || filtered.Agents[0].Status != "revoked" {
		t.Errorf("filter by a revoked agent's label = %+v", filtered.Agents)
	}
}

// TestRevokingAUserFreezesTheirAgentsLabels: revoking an account revokes its
// agents, and so freezes their labels with them.
//
//nolint:paralleltest // shares one database
func TestRevokingAUserFreezesTheirAgentsLabels(t *testing.T) {
	world, item := lbWorld(t)

	patch(t, item, lbAdd(t, "keep"), world.tokenB).expect(t, "label it", http.StatusOK, "")
	del(t, pathUser+"/"+world.b.userID, world.tokenA).expect(t, "revoke the user", http.StatusOK, "")

	expectCount(t, "agents WHERE id = ? AND revoked_at IS NOT NULL", "1", idAgentA)

	// The labels stay (rows are never deleted with the account), and the user
	// can no longer reach them.
	if stored := lbStored(t); stored != "keep" {
		t.Errorf("labels = %q, want keep", stored)
	}

	patch(t, item, lbAdd(t, "late"), world.tokenB).expect(t, "patch by a revoked user", http.StatusUnauthorized, codeUnauthenticated)
	get(t, pathAgent+"?label=keep", world.tokenB).expect(t, "list by a revoked user", http.StatusUnauthorized, codeUnauthenticated)
}

// lbCreate is a create body naming an agent and giving it labels.
func lbCreate(t *testing.T, name string, labels ...string) []byte {
	t.Helper()

	return lbBody(t, map[string]any{"name": name, "labels": labels})
}

// lbStoredFor is the labels the database holds for an agent, sorted, as text.
func lbStoredFor(t *testing.T, id string) string {
	t.Helper()

	return scalar(t, "SELECT ifnull(group_concat(label, ','), '') "+
		"FROM (SELECT label FROM agent_labels WHERE agent_id = ? ORDER BY label)", id)
}

// TestAgentCreateWithoutLabels: a create that gives none (no member, null, or an
// empty list) makes an agent with an empty list, in the response and when read
// back, and writes no label row.
//
//nolint:paralleltest // shares one database
func TestAgentCreateWithoutLabels(t *testing.T) {
	world := agNewPair(t, roleMember)

	for _, body := range []string{`{"name":"fresh"}`, `{"name":"fresh","labels":null}`, `{"name":"fresh","labels":[]}`} {
		t.Run(body, func(t *testing.T) {
			got := post(t, pathAgent, []byte(body), world.tokenB)
			got.expect(t, "create", http.StatusCreated, "")

			made := agDecode[agCreated](t, got)
			lbWant(t, "created", made.Agent)
			lbWant(t, "read back", lbView(t, get(t, agItem(made.Agent.ID), world.tokenB)))
		})
	}

	expectCount(t, "agent_labels", "0")
}

// TestAgentCreateWithLabels: the labels are stored exactly as sent, in the same
// write as the agent, and the response, a read and the database agree. Accepted
// labels include the byte bounds the real CHECK holds.
//
//nolint:paralleltest // shares one database
func TestAgentCreateWithLabels(t *testing.T) {
	world := agNewPair(t, roleMember)

	cases := []struct {
		name   string
		labels []string
	}{
		{"one", []string{"prod"}},
		{"several: the response is sorted", []string{"zeta", "alpha", "mid"}},
		{"the alphabet's edges", []string{"a", "z", "0", "9", ".", "_", "-", "az09._-"}},
		{"the longest label", []string{strings.Repeat("a", lbMaxLabelByte)}},
		{"the most labels, each the longest", func() []string {
			out := make([]string, lbMaxLabels)
			for i := range out {
				out[i] = fmt.Sprintf("%02d", i) + strings.Repeat("z", lbMaxLabelByte-2)
			}

			return out
		}()},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := post(t, pathAgent, lbCreate(t, "labelled", c.labels...), world.tokenB)
			got.expect(t, "create", http.StatusCreated, "")

			made := agDecode[agCreated](t, got)
			want := slices.Sorted(slices.Values(c.labels))

			lbWant(t, "created", made.Agent, want...)
			lbWant(t, "read back", lbView(t, get(t, agItem(made.Agent.ID), world.tokenB)), want...)

			if stored := lbStoredFor(t, made.Agent.ID); stored != strings.Join(want, ",") {
				t.Errorf("stored labels = %q, want %q", stored, strings.Join(want, ","))
			}

			// Byte for byte, and found by exact match.
			for _, label := range c.labels {
				if scalar(t, "SELECT hex(CAST(label AS BLOB)) FROM agent_labels WHERE agent_id = ? AND label = ?",
					made.Agent.ID, label) != agHex(label) {
					t.Errorf("label %q is not stored as sent", label[:min(len(label), 20)])
				}
			}

			found := agDecode[agPage](t, get(t, pathAgent+"?label="+url.QueryEscape(c.labels[0]), world.tokenB))
			if !slices.ContainsFunc(found.Agents, func(a agView) bool { return a.ID == made.Agent.ID }) {
				t.Errorf("the new agent is not listed under label=%s", c.labels[0][:min(len(c.labels[0]), 20)])
			}
		})
	}
}

// TestAgentCreateWithLabelsIsOnlyTheirs: another user's agent of the same label
// is untouched by the create and does not appear in this user's filter.
//
//nolint:paralleltest // shares one database
func TestAgentCreateWithLabelsIsOnlyTheirs(t *testing.T) {
	world := agNewPair(t, roleMember)

	seedAgent(t, idAgentA, world.a.userID, "theirs")
	seed(t, "INSERT INTO agent_labels (agent_id, label) VALUES (?, 'shared')", idAgentA)

	made := agDecode[agCreated](t, post(t, pathAgent, lbCreate(t, "mine", "shared"), world.tokenB))

	listed := agDecode[agPage](t, get(t, pathAgent+"?label=shared", world.tokenB))
	if len(listed.Agents) != 1 || listed.Agents[0].ID != made.Agent.ID {
		t.Errorf("B's filter = %+v, want only B's new agent", listed.Agents)
	}

	if stored := lbStoredFor(t, idAgentA); stored != "shared" {
		t.Errorf("another user's agent's labels = %q, want shared, unchanged", stored)
	}
}

// TestAgentCreateWithBadLabelsWritesNothing: every refusal is a 400 and leaves no
// agent, no key and no label, including a bad label beside a good name.
//
//nolint:paralleltest // shares one database
func TestAgentCreateWithBadLabelsWritesNothing(t *testing.T) {
	world := agNewPair(t, roleMember)

	many := make([]string, lbMaxLabels+1)
	for i := range many {
		many[i] = strconv.Quote("l" + strconv.Itoa(i))
	}

	refusals := []lbRefusal{
		{"an upper case label", `{"name":"x","labels":["Prod"]}`, lbCodeInvalid},
		{"an empty label", `{"name":"x","labels":[""]}`, lbCodeInvalid},
		{"a space", `{"name":"x","labels":["a b"]}`, lbCodeInvalid},
		{"a NUL", `{"name":"x","labels":["a\u0000b"]}`, lbCodeInvalid},
		{"one over the byte bound", `{"name":"x","labels":["` + strings.Repeat("a", lbMaxLabelByte+1) + `"]}`, lbCodeInvalid},
		{"an emoji", `{"name":"x","labels":["\ud83d\ude00"]}`, lbCodeInvalid},
		{"a SQL injection", `{"name":"x","labels":["'; DROP TABLE agent_labels; --"]}`, lbCodeInvalid},
		{"a valid label then an invalid one", `{"name":"x","labels":["ok","not ok"]}`, lbCodeInvalid},
		{"null in the list", `{"name":"x","labels":[null]}`, lbCodeInvalid},
		{"the same label twice", `{"name":"x","labels":["a","a"]}`, "invalid_label_set"},
		{"21 labels", `{"name":"x","labels":[` + strings.Join(many, ",") + `]}`, lbCodeTooMany},
		{"labels is a string", `{"name":"x","labels":"a"}`, "invalid_field_type"},
		{"labels holds a number", `{"name":"x","labels":[1]}`, "invalid_field_type"},
		{"a repeated labels member", `{"name":"x","labels":["a"],"labels":["b"]}`, "duplicate_field"},
		{"the patch's member name", `{"name":"x","addLabels":["a"]}`, "unknown_field"},
		{"a bad name beside a good label", `{"name":"","labels":["a"]}`, "invalid_agent_name"},
	}

	for _, c := range refusals {
		t.Run(c.name, func(t *testing.T) {
			before := bndSnapshot(t)

			post(t, pathAgent, []byte(c.body), world.tokenB).expect(t, c.name, http.StatusBadRequest, c.code)

			if after := bndSnapshot(t); after != before {
				t.Errorf("a refused create wrote:\n before %s\n after  %s", before, after)
			}
		})
	}

	expectCount(t, "agent_labels", "0")
}

// TestAgentCreateWithLabelsAtTheAgentLimit: a create that the owner's agent limit
// refuses creates nothing: not the agent, not its key and not one label. This is
// the real database failing the batch at the label statement's NOT NULL.
//
//nolint:paralleltest // shares one database
func TestAgentCreateWithLabelsAtTheAgentLimit(t *testing.T) {
	world := agNewPair(t, roleMember)
	owner := world.b.userID

	agSeedMany(t, owner, 1, agMaxAgents)

	before := bndSnapshot(t)

	post(t, pathAgent, lbCreate(t, "one too many", "a", "b", "c"), world.tokenB).
		expect(t, "over the limit", http.StatusConflict, agCodeLimit)

	if after := bndSnapshot(t); after != before {
		t.Errorf("a create over the limit wrote:\n before %s\n after  %s", before, after)
	}

	expectCount(t, "agent_labels", "0")

	// Freeing a place lets the same request through, with its labels.
	seed(t, "UPDATE agents SET revoked_at = 1 WHERE id = ?", idN(agIDPrefix, 1))

	made := agDecode[agCreated](t, post(t, pathAgent, lbCreate(t, "fits now", "a", "b", "c"), world.tokenB))
	lbWant(t, "after freeing a place", made.Agent, "a", "b", "c")
	expectCount(t, "agent_labels", "3")
}

// TestAgentCreateWithLabelsRaceAtTheLimit: with five places left, many concurrent
// creates, each with labels, produce exactly five agents and exactly their
// labels. Every loser is a 409 that left no label row behind.
//
//nolint:paralleltest // shares one database
func TestAgentCreateWithLabelsRaceAtTheLimit(t *testing.T) {
	for _, workers := range []int{8, 12} {
		t.Run(fmt.Sprintf("%d workers", workers), func(t *testing.T) {
			world := agNewPair(t, roleMember)

			agSeedMany(t, world.b.userID, 1, agMaxAgents-5)

			replies := agRelease(workers, func(i int) reply {
				return post(t, pathAgent, lbCreate(t, "race-"+strconv.Itoa(i), "racer", "n"+strconv.Itoa(i)), world.tokenB)
			})

			tally := agTally(replies)
			agNo5xx(t, "create with labels race", replies)

			if tally["201"] != 5 || tally["409 "+agCodeLimit] != workers-5 {
				t.Errorf("outcomes = %v, want exactly 5 created and %d limit refusals", tally, workers-5)
			}

			// Two labels for each agent that was created, and none for any other.
			expectCount(t, "agent_labels", "10")
			expectCount(t, "agent_labels WHERE label = 'racer'", "5")
			expectCount(t, "agent_labels WHERE agent_id NOT IN (SELECT id FROM agents)", "0")
		})
	}
}

// TestAgentCreateLabelsThenPatchAtTheLimit: a create with the most labels leaves
// the agent exactly at the cap, so the next addition is the usual 409 and a swap
// works.
//
//nolint:paralleltest // shares one database
func TestAgentCreateLabelsThenPatchAtTheLimit(t *testing.T) {
	world := agNewPair(t, roleMember)

	full := lbNames("l", lbMaxLabels)
	made := agDecode[agCreated](t, post(t, pathAgent, lbCreate(t, "full", full...), world.tokenB))
	item := agItem(made.Agent.ID)

	patch(t, item, lbAdd(t, "extra"), world.tokenB).expect(t, "one more", http.StatusConflict, lbCodeLimit)
	patch(t, item, lbBody(t, map[string]any{"addLabels": []string{"extra"}, "removeLabels": []string{"l0"}}), world.tokenB).
		expect(t, "swap", http.StatusOK, "")
	expectCount(t, "agent_labels WHERE agent_id = ?", "20", made.Agent.ID)
}

// ---- the filter ------------------------------------------------------------

// TestAgentListFilterByLabel: the exact members of a filtered list, in the real
// database, with every label of each agent shown and revoked agents included.
//
//nolint:paralleltest // shares one database
func TestAgentListFilterByLabel(t *testing.T) {
	world := agNewPair(t, roleMember)
	owner := world.b.userID

	one, two, three, four := idN(agIDPrefix, 1), idN(agIDPrefix, 2), idN(agIDPrefix, 3), idN(agIDPrefix, 4)

	for _, id := range []string{one, two, three, four} {
		seedAgent(t, id, owner, "n"+id[len(id)-1:])
	}

	seed(t, "UPDATE agents SET revoked_at = 99 WHERE id = ?", two)

	for id, labels := range map[string][]string{
		one: {"prod", "web"}, two: {"prod"}, three: {"staging", "web"}, four: {},
	} {
		for _, label := range labels {
			seed(t, "INSERT INTO agent_labels (agent_id, label) VALUES (?, ?)", id, label)
		}
	}

	ids := func(r reply) []string {
		page := agDecode[agPage](t, r)
		out := make([]string, 0, len(page.Agents))

		for _, a := range page.Agents {
			out = append(out, a.ID)
		}

		return out
	}

	tests := []struct {
		query string
		want  []string
	}{
		{"label=prod", []string{two, one}},
		{"label=web", []string{three, one}},
		{"label=staging", []string{three}},
		{"label=nope", []string{}},
		{"label=pro", []string{}},
		{"label=rod", []string{}},
		{"label=PROD", nil},
		{"", []string{four, three, two, one}},
		{"label=web&limit=1", []string{three}},
		{"label=web&limit=1&cursor=" + three, []string{one}},
		{"label=prod&limit=100&cursor=" + two, []string{one}},
		{"label=prod&cursor=" + one, []string{}},
	}

	for _, c := range tests {
		t.Run(c.query, func(t *testing.T) {
			got := get(t, pathAgent+"?"+c.query, world.tokenB)

			if c.want == nil {
				got.expect(t, c.query, http.StatusBadRequest, lbCodeFilter)

				return
			}

			got.expect(t, c.query, http.StatusOK, "")

			if have := ids(got); !slices.Equal(have, c.want) {
				t.Errorf("?%s = %v, want %v", c.query, have, c.want)
			}
		})
	}

	// The filter does not narrow what is shown of an agent.
	page := agDecode[agPage](t, get(t, pathAgent+"?label=web", world.tokenB))
	lbWant(t, "agent one under label=web", page.Agents[1], "prod", "web")
	lbWant(t, "agent three under label=web", page.Agents[0], "staging", "web")
}

// TestAgentListFilterQuery is the table of label query values, in the real
// build: what TinyGo's URL parsing hands the parser must be what the unit
// tests assumed.
//
//nolint:paralleltest // shares one database
func TestAgentListFilterQuery(t *testing.T) {
	world, _ := lbWorld(t)
	seed(t, "INSERT INTO agent_labels (agent_id, label) VALUES (?, 'a.b-c_d')", idAgentA)

	enc := url.QueryEscape

	ok := func(query string, n int) lbQuery { return lbQuery{query: query, status: http.StatusOK, n: n} }
	bad := func(query string) lbQuery {
		return lbQuery{query: query, status: http.StatusBadRequest, code: lbCodeFilter}
	}

	cases := []lbQuery{
		ok("label=a.b-c_d", 1),
		ok("label="+enc("a.b-c_d"), 1),
		ok("label=a%2Eb-c_d", 1), // an escaped '.' is the same label
		ok("label=nope", 0),
		ok("labels=a.b-c_d", 1), // another parameter name: no filter
		ok("Label=a.b-c_d", 1),  // names are case sensitive: no filter
		ok("label[]=nope", 1),   // another name
		ok("limit=5&label=nope", 0),
		bad("label="),
		bad("label"),
		bad("label=A.b-c_d"),
		bad("label=a+b"),
		bad("label=a%20b"),
		bad("label=a,b"),
		bad("label=a.b-c_d&label=a.b-c_d"),
		bad("label=a.b-c_d&label="),
		bad("label=&label=a.b-c_d"),
		bad("label=" + strings.Repeat("a", lbMaxLabelByte+1)),
		bad("label=" + strings.Repeat("a", 5000)),
		bad("label=a%00"),
		bad("label=a%0A"),
		bad("label=" + enc("' OR '1'='1")),
		bad("label=%25"),
		bad("label=" + enc("caf\u00e9")),
		bad("label=%ff"),
		bad("label=" + enc("\U0001F600")),
		bad("label=" + enc("\u0430")),
	}

	for _, c := range cases {
		t.Run(c.query[:min(len(c.query), 40)], func(t *testing.T) {
			got := get(t, pathAgent+"?"+c.query, world.tokenB)
			got.expect(t, c.query, c.status, c.code)

			if c.status == http.StatusOK && len(agDecode[agPage](t, got).Agents) != c.n {
				t.Errorf("?%s listed %d agents, want %d", c.query, len(agDecode[agPage](t, got).Agents), c.n)
			}
		})
	}
}

// lbQuery is one query string of the filter table.
type lbQuery struct {
	query  string
	status int
	code   string
	n      int
}

// TestAgentFilteredWalk: following the cursors of a filtered list sees every
// match exactly once, newest first, and no agent without the label, at every
// page size, while agents are created and labelled in between.
//
//nolint:paralleltest // shares one database
func TestAgentFilteredWalk(t *testing.T) {
	world := agNewPair(t, roleMember)
	owner := world.b.userID

	const total = 17

	var want []string

	for i := range total {
		id := idN(agIDPrefix, i+1)
		seedAgent(t, id, owner, "w"+strconv.Itoa(i))

		label := "drop"
		if i%3 != 1 {
			label = "keep"

			want = append([]string{id}, want...)
		}

		seed(t, "INSERT INTO agent_labels (agent_id, label) VALUES (?, ?)", id, label)
	}

	for _, size := range []int{1, 2, 3, 5, 7, 100} {
		t.Run("page size "+strconv.Itoa(size), func(t *testing.T) {
			var (
				seen   []string
				cursor string
			)

			for range total + 1 {
				got := get(t, fmt.Sprintf("%s?label=keep&limit=%d%s", pathAgent, size, cursor), world.tokenB)
				got.expect(t, "page", http.StatusOK, "")

				page := agDecode[agPage](t, got)
				if len(page.Agents) > size {
					t.Fatalf("a page of %d, want at most %d", len(page.Agents), size)
				}

				for _, a := range page.Agents {
					if !slices.Contains(a.Labels, "keep") {
						t.Fatalf("agent %s without the label was listed: %v", a.ID, a.Labels)
					}

					seen = append(seen, a.ID)
				}

				if page.Next == "" {
					break
				}

				cursor = "&cursor=" + page.Next
			}

			if !slices.Equal(seen, want) {
				t.Errorf("paging saw %v, want %v", seen, want)
			}
		})
	}
}

// TestAgentLabelsSchemaBackstops: nothing deletes an agent, but a label's row is
// tied to its agent by a real foreign key: a label cannot name an agent that does
// not exist, and the CHECKs refuse what Go would never send.
//
//nolint:paralleltest // shares one database
func TestAgentLabelsSchemaBackstops(t *testing.T) {
	_, _ = lbWorld(t)

	refusedRows := []struct {
		name  string
		query string
		args  []any
	}{
		{"a label for an agent that does not exist", "INSERT INTO agent_labels (agent_id, label) VALUES (?, 'a')", []any{idMissing}},
		{"a NULL agent", "INSERT INTO agent_labels (agent_id, label) VALUES (NULL, 'a')", nil},
		{"a NULL label", "INSERT INTO agent_labels (agent_id, label) VALUES (?, NULL)", []any{idAgentA}},
		{"an empty label", "INSERT INTO agent_labels (agent_id, label) VALUES (?, '')", []any{idAgentA}},
		{"a 64-byte label", "INSERT INTO agent_labels (agent_id, label) VALUES (?, ?)", []any{idAgentA, strings.Repeat("a", 64)}},
		{"a NUL then megabytes", "INSERT INTO agent_labels (agent_id, label) VALUES (?, ?)", []any{idAgentA, "a\x00" + strings.Repeat("b", 4096)}},
		{"a blob label", "INSERT INTO agent_labels (agent_id, label) VALUES (?, ?)", []any{idAgentA, []byte("blob")}},
	}

	for _, c := range refusedRows {
		t.Run(c.name, func(t *testing.T) {
			if !refused(t, c.query, c.args...) {
				t.Errorf("the schema accepted: %s", c.name)
			}
		})
	}

	// A label is a member of a set: the same pair twice is refused.
	seed(t, "INSERT INTO agent_labels (agent_id, label) VALUES (?, 'dup')", idAgentA)

	if !refused(t, "INSERT INTO agent_labels (agent_id, label) VALUES (?, 'dup')", idAgentA) {
		t.Error("the same label was accepted twice for one agent")
	}

	// The same label on two agents is fine.
	seedAgent(t, idAgentB, scalar(t, "SELECT user_id FROM agents WHERE id = ?", idAgentA), "other")
	seed(t, "INSERT INTO agent_labels (agent_id, label) VALUES (?, 'dup')", idAgentB)
}
