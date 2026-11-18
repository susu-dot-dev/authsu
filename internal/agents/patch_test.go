package agents_test

import (
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/store"
)

const (
	codeNothingToChange = "missing_agent_change"
	codeRevoked         = "agent_revoked"
	codeLabelLimit      = "agent_label_limit_reached"
	codeInvalidLabel    = "invalid_agent_label"
	codeLabelPatch      = "invalid_label_patch"
	codeLabelFilter     = "invalid_label_filter"
	codeTooManyItems    = "too_many_items"

	bodyLabelLimit = `{"error":{"code":"agent_label_limit_reached",` +
		`"message":"an agent may have at most 20 labels"}}` + "\n"

	bodyRemoveA = `{"removeLabels":["a"]}`
	bodyAddA    = `{"addLabels":["a"]}`
)

// patchCase is one row of TestPatch: an agent, a body, and what the patch leaves.
type patchCase struct {
	name   string
	agent  store.Agent
	body   string
	status int
	// want is the exact response body of a 200, or the failure's body.
	want string
	// code is the logged code of a failure.
	code string
	// after is the agent as stored afterwards.
	after store.Agent
}

// bodyRevoked is the exact refusal of a change to a revoked agent.
const bodyRevoked = `{"error":{"code":"agent_revoked","message":"the agent is revoked and cannot be changed"}}` + "\n"

// ok is a patch that succeeds: the agent comes back as want and is stored as after.
func ok(name string, agent store.Agent, body string, want, after store.Agent) patchCase {
	return patchCase{
		name: name, agent: agent, body: body, status: http.StatusOK,
		want: agentJSONWith(want.ID, want.Name, want.CreatedAt, want.RevokedAt, labelsText(want.Labels)), code: "",
		after: after,
	}
}

// conflict is a patch that is refused with a 409, the body and logged code of
// want and code, and leaves the agent as it was.
func conflict(name string, agent store.Agent, body, want, code string) patchCase {
	return patchCase{
		name: name, agent: agent, body: body, status: http.StatusConflict, want: want, code: code, after: agent,
	}
}

// labelsText is the JSON text of labels as a response lists them: sorted.
func labelsText(labels []string) string { return sortedJSON(labels) }

// patchFixtures are the agents the rows of TestPatch start from.
type patchFixtures struct {
	active, revoked, atLimit, below store.Agent
}

func newPatchFixtures() patchFixtures {
	active := stored(agentA1, nameAlpha, 100, nil)

	return patchFixtures{
		active:  active,
		revoked: stored(agentA1, nameAlpha, 100, new(int64(150))),
		atLimit: labelled(active, labelsUpTo(input.MaxLabelsPerAgent)...),
		below:   labelled(active, labelsUpTo(input.MaxLabelsPerAgent-1)...),
	}
}

// renamed is agent with another name.
func renamed(agent store.Agent, name string) store.Agent {
	agent.Name = name

	return agent
}

// patchCases are the rows of TestPatch. Each starts from one agent.
func patchCases() []patchCase {
	return slices.Concat(renameCases(), addCases(), removeCases(), bothCases(), frozenCases())
}

func renameCases() []patchCase {
	f := newPatchFixtures()

	return []patchCase{
		ok("rename an active agent", f.active, bodyRenamed, renamed(f.active, "renamed"), renamed(f.active, "renamed")),
		ok("the same name", f.active, `{"name":"alpha"}`, f.active, f.active),
		ok("a name kept as sent", f.active, `{"name":"  b  "}`, renamed(f.active, "  b  "), renamed(f.active, "  b  ")),
		conflict("a revoked agent keeps its name", f.revoked, bodyRenamed, bodyRevoked, codeRevoked),
	}
}

func addCases() []patchCase {
	f := newPatchFixtures()
	last := slices.Concat(labelsUpTo(input.MaxLabelsPerAgent-1), []string{"last"})

	return []patchCase{
		ok("add one label", f.active, `{"addLabels":["prod"]}`,
			labelled(f.active, "prod"), labelled(f.active, "prod")),
		ok("add several labels: the response is sorted", f.active, `{"addLabels":["zeta","alpha","mid"]}`,
			labelled(f.active, "alpha", "mid", "zeta"), labelled(f.active, "zeta", "alpha", "mid")),
		ok("add a label the agent has: a no-op", labelled(f.active, "prod"), `{"addLabels":["prod"]}`,
			labelled(f.active, "prod"), labelled(f.active, "prod")),
		ok("add to an agent that has others", labelled(f.active, "a", "b"), `{"addLabels":["c"]}`,
			labelled(f.active, "a", "b", "c"), labelled(f.active, "a", "b", "c")),
		ok("add up to the limit", f.below, `{"addLabels":["last"]}`,
			labelled(f.active, last...), labelled(f.active, last...)),
		conflict("one over the limit changes nothing", f.atLimit, `{"addLabels":["extra"]}`,
			bodyLabelLimit, codeLabelLimit),
		ok("re-adding at the limit is not over it", f.atLimit, `{"addLabels":["`+labelName(0)+`"]}`, f.atLimit, f.atLimit),
		conflict("a rename is not applied when the labels are over the limit", f.atLimit,
			`{"name":"renamed","addLabels":["extra"]}`, bodyLabelLimit, codeLabelLimit),
	}
}

func removeCases() []patchCase {
	f := newPatchFixtures()

	return []patchCase{
		ok("remove one label", labelled(f.active, "a", "b"), bodyRemoveA, labelled(f.active, "b"), labelled(f.active, "b")),
		ok("remove the last label", labelled(f.active, "a"), bodyRemoveA, f.active, f.active),
		ok("remove a label the agent lacks: a no-op", labelled(f.active, "a"), `{"removeLabels":["z"]}`,
			labelled(f.active, "a"), labelled(f.active, "a")),
		ok("remove from an agent with none", f.active, `{"removeLabels":["z"]}`, f.active, f.active),
	}
}

func bothCases() []patchCase {
	f := newPatchFixtures()
	swapped := slices.Concat(labelsUpTo(input.MaxLabelsPerAgent)[1:], []string{"fresh"})
	both := renamed(f.active, "renamed")

	return []patchCase{
		ok("add and remove", labelled(f.active, "a", "b"), `{"addLabels":["c"],"removeLabels":["a"]}`,
			labelled(f.active, "b", "c"), labelled(f.active, "b", "c")),
		ok("swap one label for another at the limit: removals come first", f.atLimit,
			`{"addLabels":["fresh"],"removeLabels":["`+labelName(0)+`"]}`,
			labelled(f.active, swapped...), labelled(f.active, swapped...)),
		ok("rename and labels together", labelled(f.active, "a"),
			`{"name":"renamed","addLabels":["b"],"removeLabels":["a"]}`,
			labelled(both, "b"), labelled(both, "b")),
		ok("null members are absent", labelled(f.active, "a"),
			`{"name":"renamed","addLabels":null,"removeLabels":null}`,
			labelled(both, "a"), labelled(both, "a")),
	}
}

// frozenCases are the changes to a revoked agent: it is final.
func frozenCases() []patchCase {
	f := newPatchFixtures()

	return []patchCase{
		conflict("labels of a revoked agent are not added", f.revoked, bodyAddA, bodyRevoked, codeRevoked),
		conflict("labels of a revoked agent are not removed", labelled(f.revoked, "a"), bodyRemoveA,
			bodyRevoked, codeRevoked),
	}
}

// TestPatch: the agent comes back as the batch left it, and the store is asked,
// for the session's user, to patch exactly the agent in the path. Each case
// starts from one agent and says what the patch leaves.
func TestPatch(t *testing.T) {
	t.Parallel()

	for _, tt := range patchCases() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, tt.agent)

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, itemPrefix+agentA1, tt.body)

			if tt.status == http.StatusOK {
				wantOK(t, rg, rec, tt.status, tt.want+"\n")
			} else {
				wantFailure(t, rg, rec, tt.status, tt.want, tt.code)
			}

			if got := rg.store.agent(t, agentA1); !sameAgent(got, tt.after) {
				t.Errorf("the agent is %+v afterwards, want %+v", got, tt.after)
			}

			if len(rg.store.calls) != 1 || rg.store.calls[0].method != methodPatch ||
				rg.store.calls[0].owner != userA || rg.store.calls[0].id != agentA1 {
				t.Errorf("store calls = %+v, want one patch of %s for %s", rg.store.calls, agentA1, userA)
			}
		})
	}
}

// TestPatchAsksTheStoreForExactlyWhatWasSent: the parsed patch, the limit and the
// order the labels were sent in reach the store unchanged.
func TestPatchAsksTheStoreForExactlyWhatWasSent(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rg.seed(userA, stored(agentA1, nameAlpha, 100, nil))

	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, itemPrefix+agentA1,
		`{"name":"n","addLabels":["z","a"],"removeLabels":["m"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
	}

	patch := rg.store.calls[0].patch

	if patch.Name == nil || patch.Name.String() != "n" {
		t.Errorf("name = %v, want n", patch.Name)
	}

	if got := labelTexts(patch.Labels.Add()); !reflect.DeepEqual(got, []string{"z", "a"}) {
		t.Errorf("add = %v, want [z a] in the order sent", got)
	}

	if got := labelTexts(patch.Labels.Remove()); !reflect.DeepEqual(got, []string{"m"}) {
		t.Errorf("remove = %v, want [m]", got)
	}

	if patch.MaxLabels != input.MaxLabelsPerAgent {
		t.Errorf("MaxLabels = %d, want %d", patch.MaxLabels, input.MaxLabelsPerAgent)
	}

	// A patch with no name sends none: nil, not an empty name.
	rg2 := newRig(t)
	rg2.seed(userA, stored(agentA1, nameAlpha, 100, nil))
	rg2.as(rg2.signIn(userA, roleMember), http.MethodPatch, itemPrefix+agentA1, bodyAddA)

	if rg2.store.calls[0].patch.Name != nil {
		t.Errorf("a patch without a name carries %v", rg2.store.calls[0].patch.Name)
	}
}

// TestPatchFindsNothingToChange: an agent that does not exist.
func TestPatchFindsNothingToChange(t *testing.T) {
	t.Parallel()

	for _, body := range []string{bodyX, bodyAddA, bodyRemoveA} {
		t.Run(body, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(agentA1, nameAlpha, 100, nil))

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, itemPrefix+nobody, body)

			wantFailure(t, rg, rec, http.StatusNotFound, bodyNotFound, codeNotFound)

			if got := rg.store.agent(t, agentA1); !sameAgent(got, stored(agentA1, nameAlpha, 100, nil)) {
				t.Errorf("another agent changed to %+v", got)
			}
		})
	}
}

// badBody is a PATCH body that is refused, with its status and code.
type badBody struct {
	name   string
	body   string
	status int
	code   string
}

// rejects is a 400 with a code.
func rejects(name, body, code string) badBody {
	return badBody{name: name, body: body, status: http.StatusBadRequest, code: code}
}

// badLabel is a body that adds label, which must be refused as an invalid label.
func badLabel(name, label string) badBody {
	return rejects(name, `{"addLabels":[`+strconv.Quote(label)+`]}`, codeInvalidLabel)
}

// badLabelJSON is a body whose label is spelled with a JSON escape.
func badLabelJSON(name, escaped string) badBody {
	return rejects(name, `{"addLabels":["`+escaped+`"]}`, codeInvalidLabel)
}

// nothingRefusals are the bodies that change nothing.
func nothingRefusals() []badBody {
	return []badBody{
		rejects("no body", "", "empty_body"),
		rejects("an empty object", `{}`, codeNothingToChange),
		rejects("a null name", `{"name":null}`, codeNothingToChange),
		rejects("all members null", `{"name":null,"addLabels":null,"removeLabels":null}`, codeNothingToChange),
		rejects("empty lists", `{"addLabels":[],"removeLabels":[]}`, codeNothingToChange),
	}
}

// nameRefusals are the invalid names, as for a create.
func nameRefusals() []badBody {
	long := strings.Repeat("a", 257)

	return []badBody{
		rejects("an empty name", `{"name":""}`, codeInvalidName),
		rejects("a blank name", `{"name":"   "}`, codeInvalidName),
		rejects("a control character", `{"name":"a\u0000b"}`, codeInvalidName),
		rejects("a format character", `{"name":"a\u200bb"}`, codeInvalidName),
		rejects("a bidi override", `{"name":"a\u202eb"}`, codeInvalidName),
		rejects("decomposed text", `{"name":"cafe\u0301"}`, codeInvalidName),
		rejects("too long", nameBodyOf(long), codeInvalidName),
		rejects("too long in four-byte characters", nameBodyOf(strings.Repeat("\U0001F600", 257)), codeInvalidName),
		rejects("a name that is a number", `{"name":5}`, codeFieldType),
		rejects("an invalid name beside valid labels", `{"name":"","addLabels":["a"]}`, codeInvalidName),
	}
}

// labelRefusals are the invalid labels and combinations of labels.
func labelRefusals() []badBody {
	over := make([]string, input.MaxLabelsPerPatch+1)
	for i := range over {
		over[i] = strconv.Quote(labelName(i))
	}

	manyJSON := `[` + strings.Join(over, ",") + `]`

	return []badBody{
		badLabel("an upper case label", "Prod"),
		rejects("an upper case label removed", `{"removeLabels":["Prod"]}`, codeInvalidLabel),
		badLabel("an empty label", ""),
		badLabel("a label with a space", "a b"),
		badLabelJSON("a label with a NUL", `a\u0000`),
		badLabelJSON("a label with a newline", `a\n`),
		badLabelJSON("a label of another script", `\u0430`),
		badLabelJSON("an emoji label", `\ud83d\ude00`),
		badLabelJSON("a decomposed label", `cafe\u0301`),
		badLabel("a label one over the limit", strings.Repeat("a", 64)),
		rejects("a valid label then an invalid one", `{"addLabels":["ok","not ok"]}`, codeInvalidLabel),
		rejects("the same label twice", `{"addLabels":["a","a"]}`, codeLabelPatch),
		rejects("the same label removed twice", `{"removeLabels":["a","a"]}`, codeLabelPatch),
		rejects("a label added and removed", `{"addLabels":["a"],"removeLabels":["a"]}`, codeLabelPatch),
		rejects("too many labels to add", `{"addLabels":`+manyJSON+`}`, codeTooManyItems),
		rejects("too many labels to remove", `{"removeLabels":`+manyJSON+`}`, codeTooManyItems),
	}
}

// shapeRefusals are the bodies of the wrong shape.
func shapeRefusals() []badBody {
	return []badBody{
		rejects("addLabels is a string", `{"addLabels":"a"}`, codeFieldType),
		rejects("addLabels is an object", `{"addLabels":{"a":1}}`, codeFieldType),
		rejects("addLabels holds a number", `{"addLabels":[1]}`, codeFieldType),
		rejects("addLabels holds null", `{"addLabels":[null]}`, codeInvalidLabel),
		rejects("addLabels holds an array", `{"addLabels":[["a"]]}`, codeFieldType),
		rejects("removeLabels is a string", `{"removeLabels":"a"}`, codeFieldType),
		rejects("a repeated addLabels", `{"addLabels":["a"],"addLabels":["b"]}`, codeDuplicate),
		rejects("labels is not a member", `{"labels":["a"]}`, codeUnknownField),
		rejects("a different case member", `{"AddLabels":["a"]}`, codeUnknownField),
		rejects("a snake case member", `{"add_labels":["a"]}`, codeUnknownField),
		rejects("not json", `name=x`, codeInvalidJSON),
		rejects("an unknown member", `{"name":"a","revoked":true}`, codeUnknownField),
		rejects("a repeated name", `{"name":"a","name":"b"}`, codeDuplicate),
		rejects("trailing data", `{"name":"a"}x`, "trailing_data"),
	}
}

// TestPatchRefusesWhatItCannotUse: every refusal is a 400 with its code, and
// nothing reaches the store.
func TestPatchRefusesWhatItCannotUse(t *testing.T) {
	t.Parallel()

	all := slices.Concat(nothingRefusals(), nameRefusals(), labelRefusals(), shapeRefusals())

	for _, tt := range all {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(agentA1, nameAlpha, 100, nil))

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, itemPrefix+agentA1, tt.body)

			wantCode(t, rg, rec, tt.status, tt.code)
			rg.untouched()
		})
	}
}

// nameBodyOf is the body of a request naming name, for a table built outside a
// test.
func nameBodyOf(name string) string { return `{"name":"` + name + `"}` }

// TestPatchNothingToChangeMessage pins the exact refusal of an empty patch.
func TestPatchNothingToChangeMessage(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, itemPrefix+agentA1, `{}`)

	wantFailure(t, rg, rec, http.StatusBadRequest,
		errorBody(codeNothingToChange, "a name, labels to add or labels to remove is required"), codeNothingToChange)
}

// TestPatchAcceptsNamesAtTheLimit: the bounds are those of a create, in
// characters, whatever their width in bytes, and the name is stored as sent.
func TestPatchAcceptsNamesAtTheLimit(t *testing.T) {
	t.Parallel()

	widths := []struct {
		name string
		char string
	}{
		{name: "one byte", char: "a"},
		{name: "two bytes", char: "\u00e9"},
		{name: "four bytes", char: "\U0001F600"},
	}

	for _, tt := range widths {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(agentA1, nameAlpha, 100, nil))

			name := strings.Repeat(tt.char, 256)
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, itemPrefix+agentA1, nameBody(t, name))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %.200q, want 200", rec.Code, rec.Body.String())
			}

			if got := rg.store.agent(t, agentA1).Name; got != name || len(got) > 1024 {
				t.Errorf("stored %d bytes, want the %d-byte name as sent", len(got), len(name))
			}
		})
	}
}

// TestPatchAcceptsTheMostLabelsARequestMay: the largest accepted arrays are
// handled in full, at the bound where the decoder refuses the next item.
func TestPatchAcceptsTheMostLabelsARequestMay(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	rg.seed(userA, stored(agentA1, nameAlpha, 100, nil))

	all := labelsUpTo(input.MaxLabelsPerPatch)
	quoted := make([]string, len(all))

	for i, label := range all {
		quoted[i] = strconv.Quote(label)
	}

	longest := strings.Repeat("z", input.MaxLabelBytes)
	body := `{"addLabels":[` + strings.Join(quoted, ",") + `],"removeLabels":["` + longest + `"]}`

	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, itemPrefix+agentA1, body)

	wantOK(t, rg, rec, http.StatusOK, agentJSONWith(agentA1, nameAlpha, 100, nil, sortedJSON(all))+"\n")
}

// TestPatchStoreFailures: the ways the store fails a patch reach the client
// classified, and a conflict that is not the label limit's cannot occur.
func TestPatchStoreFailures(t *testing.T) {
	t.Parallel()

	for _, failure := range storeFailures(store.CodeAgentUpdateFailed, store.CodeAgentUpdateRejected) {
		t.Run(failure.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userA, stored(agentA1, nameAlpha, 1, nil))
			rg.store.failures[methodPatch] = failure.err

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, itemPrefix+agentA1, bodyAddA)

			wantFailure(t, rg, rec, failure.status, failure.body, failure.logged)
		})
	}
}

// labelName is the n-th label of a family of valid labels.
func labelName(n int) string { return "label-" + strconv.Itoa(n) }

// labelsUpTo is n valid labels, label-0 to label-(n-1).
func labelsUpTo(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = labelName(i)
	}

	return out
}

// sortedJSON is the JSON text of labels as a response lists them: sorted.
func sortedJSON(labels []string) string {
	sorted := append([]string(nil), labels...)

	for i := range sorted {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	quoted := make([]string, len(sorted))
	for i, label := range sorted {
		quoted[i] = strconv.Quote(label)
	}

	return "[" + strings.Join(quoted, ",") + "]"
}

// labelTexts is the text of each label.
func labelTexts(labels []input.Label) []string {
	out := make([]string, len(labels))
	for i, label := range labels {
		out[i] = label.String()
	}

	return out
}
