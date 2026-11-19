package agents_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/agents"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// codeLabelSet is the refusal of a create whose labels are a bad set.
const codeLabelSet = "invalid_label_set"

// agentFrom decodes the agent a successful read returned.
func agentFrom(t *testing.T, rec *httptest.ResponseRecorder) agents.Agent {
	t.Helper()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %.300q, want 200", rec.Code, rec.Body.String())
	}

	var agent agents.Agent

	err := json.Unmarshal(rec.Body.Bytes(), &agent)
	if err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}

	return agent
}

// listFrom decodes the page a successful list returned.
func listFrom(t *testing.T, rec *httptest.ResponseRecorder) agents.ListResponse {
	t.Helper()

	if rec.Code != http.StatusOK {
		return agents.ListResponse{}
	}

	var page agents.ListResponse

	err := json.Unmarshal(rec.Body.Bytes(), &page)
	if err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}

	return page
}

// errLimitRefusal is what the store returns for a create that the owner's limit or
// revocation refused: the sentinel the feature answers as the limit.
var errLimitRefusal = store.Classify(errNotNull)

// labelledBody is a create body for an agent named "a" whose labels member is the
// raw JSON given, or left out when raw is empty.
func labelledBody(raw string) string {
	if raw == "" {
		return `{"name":"a"}`
	}

	return `{"name":"a","labels":` + raw + `}`
}

// quotedLabels is the JSON array of labels.
func quotedLabels(labels []string) string {
	quoted := make([]string, len(labels))
	for i, label := range labels {
		quoted[i] = jsonString(label)
	}

	return "[" + strings.Join(quoted, ",") + "]"
}

// jsonString is s as a JSON string. strconv.Quote is Go syntax and not JSON: it
// writes a NUL as \x00, which JSON has no escape for.
func jsonString(s string) string {
	encoded, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}

	return string(encoded)
}

// writtenLabels is the labels a create handed to the store, in the order it
// handed them.
func writtenLabels(t *testing.T, rg *rig) []string {
	t.Helper()

	if len(rg.store.calls) != 1 || rg.store.calls[0].method != methodCreate {
		t.Fatalf("store calls = %+v, want one create", rg.store.calls)
	}

	labels := rg.store.calls[0].agent.Labels.Labels()
	text := make([]string, len(labels))

	for i, label := range labels {
		text[i] = label.String()
	}

	return text
}

// TestCreateAcceptsLabels: what a create gives the new agent, for each way of
// sending labels. The write gets them in the order sent, and the response lists
// them in ascending order, as a read of the agent does, with the same labels the
// store holds.
func TestCreateAcceptsLabels(t *testing.T) {
	t.Parallel()

	longest := strings.Repeat("z", input.MaxLabelBytes)

	tests := []struct {
		name string
		body string
		// written is what the store is given, and shown what the response lists.
		written, shown []string
	}{
		{"no labels member", labelledBody(""), strs(), strs()},
		{"a null list", labelledBody("null"), strs(), strs()},
		{"an empty list", labelledBody("[]"), strs(), strs()},
		{"one label", labelledBody(`["prod"]`), strs("prod"), strs("prod")},
		{"several: written as sent, shown sorted", labelledBody(`["zeta","alpha","mid"]`),
			strs("zeta", "alpha", "mid"), strs("alpha", "mid", "zeta")},
		{"every character of the alphabet", labelledBody(`["az09._-"]`), strs("az09._-"), strs("az09._-")},
		{"the longest label", labelledBody(`["` + longest + `"]`), strs(longest), strs(longest)},
		{"a label escaped in JSON", labelledBody(`["pr\u006fd"]`), strs("prod"), strs("prod")},
		{"the most labels", labelledBody(quotedLabels(labelsUpTo(input.MaxLabelsPerCreate))),
			labelsUpTo(input.MaxLabelsPerCreate), sortedCopy(labelsUpTo(input.MaxLabelsPerCreate))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, tt.body)

			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, body %.300q, want 201", rec.Code, rec.Body.String())
			}

			response := created(t, rec.Body.Bytes())

			if response.Agent.Labels == nil || !slices.Equal(response.Agent.Labels, tt.shown) {
				t.Errorf("response labels = %#v, want %#v", response.Agent.Labels, tt.shown)
			}

			if got := writtenLabels(t, rg); !slices.Equal(got, tt.written) {
				t.Errorf("written labels = %#v, want %#v", got, tt.written)
			}

			// A read of the agent agrees with the response.
			read := rg.as(rg.signIn(userA, roleMember), http.MethodGet, itemPrefix+newAgentID, "")
			if got := agentFrom(t, read).Labels; !slices.Equal(got, tt.shown) {
				t.Errorf("a read of the new agent lists %#v, want %#v", got, tt.shown)
			}
		})
	}
}

// sortedCopy is labels in ascending order, leaving labels as it was.
func sortedCopy(labels []string) []string { return slices.Sorted(slices.Values(labels)) }

// badLabelBodies are the create bodies a bad labels member makes, and what each
// is refused as.
func badLabelBodies() []badBody {
	tooMany := quotedLabels(labelsUpTo(input.MaxLabelsPerCreate + 1))

	bad := func(name, label string) badBody {
		return rejects(name, labelledBody(`[`+jsonString(label)+`]`), codeInvalidLabel)
	}

	return []badBody{
		bad("an upper case label", "Prod"),
		bad("an empty label", ""),
		bad("a label with a space", "a b"),
		bad("a label with a NUL", "a\x00b"),
		bad("a label with a newline", "a\n"),
		bad("a label of another script", "\u0430"),
		bad("an emoji label", "\U0001F600"),
		bad("a decomposed label", "cafe\u0301"),
		bad("a zero-width space", "a\u200bb"),
		bad("a SQL-looking label", "'; DROP TABLE agent_labels; --"),
		bad("a pattern character", "a%"),
		bad("a label one over the limit", strings.Repeat("a", input.MaxLabelBytes+1)),
		bad("a label far over the limit", strings.Repeat("a", 5000)),
		rejects("a valid label then an invalid one", labelledBody(`["ok","not ok"]`), codeInvalidLabel),
		rejects("an invalid label then a repeat", labelledBody(`["A","a","a"]`), codeInvalidLabel),
		rejects("a null in the list", labelledBody(`[null]`), codeInvalidLabel),
		rejects("the same label twice", labelledBody(`["a","a"]`), codeLabelSet),
		rejects("the same label twice, apart", labelledBody(`["a","b","a"]`), codeLabelSet),
		rejects("one label too many", labelledBody(tooMany), codeTooManyItems),
		rejects("many more than the limit, within the body cap", labelledBody(quotedLabels(labelsUpTo(300))),
			codeTooManyItems),
		// So many that the body cap is reached first: refused before any item is read.
		{name: "so many labels that the body is over the cap", body: labelledBody(quotedLabels(labelsUpTo(5000))),
			status: http.StatusRequestEntityTooLarge, code: "body_too_large"},
		rejects("labels is a string", labelledBody(`"a"`), codeFieldType),
		rejects("labels is an object", labelledBody(`{"a":1}`), codeFieldType),
		rejects("labels is a number", labelledBody(`5`), codeFieldType),
		rejects("labels is a bool", labelledBody(`true`), codeFieldType),
		rejects("labels holds a number", labelledBody(`[1]`), codeFieldType),
		rejects("labels holds an array", labelledBody(`[["a"]]`), codeFieldType),
		rejects("labels holds a bool", labelledBody(`[true]`), codeFieldType),
		rejects("a repeated labels member", `{"name":"a","labels":["a"],"labels":["b"]}`, codeDuplicate),
		rejects("a repeated labels member by escaped spelling", `{"name":"a","labels":["a"],"lab\u0065ls":["b"]}`,
			codeDuplicate),
		rejects("a member in another case", `{"name":"a","Labels":["a"]}`, codeUnknownField),
		rejects("the patch's member name", `{"name":"a","addLabels":["a"]}`, codeUnknownField),
		rejects("invalid UTF-8 in a label", "{\"name\":\"a\",\"labels\":[\"a\xffb\"]}", codeInvalidText),
		rejects("a lone surrogate in a label", `{"name":"a","labels":["a\ud800"]}`, codeInvalidText),
		rejects("truncated inside the labels", `{"name":"a","labels":["a"`, codeInvalidJSON),
		// A bad name is refused as it always was, and a good label does not save it.
		rejects("a bad name beside good labels", `{"name":"","labels":["a"]}`, codeInvalidName),
		// Neither does a good name save a bad label.
		rejects("a good name beside a bad label", `{"name":"fine","labels":["BAD"]}`, codeInvalidLabel),
	}
}

// TestCreateRefusesBadLabels: every refusal is a 400 with its code, before a key
// is created and before anything is written, whatever else the body holds.
func TestCreateRefusesBadLabels(t *testing.T) {
	t.Parallel()

	for _, tt := range badLabelBodies() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, tt.body)

			wantCode(t, rg, rec, tt.status, tt.code)
			rg.untouched()
		})
	}
}

// TestCreateLabelRefusalsAreFixed pins the exact body of the refusals a client
// reads, once, and shows that the label sent is never echoed back.
func TestCreateLabelRefusalsAreFixed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, body, code, message string
	}{
		{"an invalid label", labelledBody(`["Secret-Value"]`), codeInvalidLabel,
			"label must be 1 to 63 characters, each a lower-case letter, a digit, '.', '_' or '-'"},
		{"a repeated label", labelledBody(`["dup","dup"]`), codeLabelSet,
			"labels must be at most 20 in number, and none may be given twice"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, tt.body)

			wantFailure(t, rg, rec, http.StatusBadRequest, errorBody(tt.code, tt.message), tt.code)

			for _, echoed := range []string{"Secret-Value", "dup"} {
				if strings.Contains(rec.Body.String(), echoed) {
					t.Errorf("the refusal %q echoes the label %q", rec.Body.String(), echoed)
				}
			}

			rg.untouched()
		})
	}
}

// TestCreateLabelsFitTheBodyCap: the largest create a client can have a reason to
// send, twenty of the longest labels beside the longest name, fits the cap with
// room to spare, so the cap refuses nothing legitimate.
func TestCreateLabelsFitTheBodyCap(t *testing.T) {
	t.Parallel()

	longest := make([]string, input.MaxLabelsPerCreate)
	for i := range longest {
		longest[i] = longestLabel(i)
	}

	body := `{"name":"` + strings.Repeat(`\ud83d\ude00`, 256) + `","labels":` + quotedLabels(longest) + `}`
	if len(body) > agents.MaxBody*3/4 {
		t.Fatalf("largest legitimate create is %d bytes, over three quarters of the %d cap", len(body), agents.MaxBody)
	}

	rg := newRig(t)
	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, body)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %.300s", rec.Code, rec.Body)
	}

	if got := writtenLabels(t, rg); !slices.Equal(got, longest) {
		t.Errorf("written %d labels, want the %d sent", len(got), len(longest))
	}
}

// longestLabel is the n-th of labels that are all exactly the longest length.
func longestLabel(n int) string {
	prefix := strconv.Itoa(n) + "-"

	return prefix + strings.Repeat("z", input.MaxLabelBytes-len(prefix))
}

// TestCreateWithLabelsFailsWhole: a create the store refuses leaves neither the
// agent nor its labels behind, and tells the client what it tells for a create
// without labels. A create with labels has no outcome of its own.
func TestCreateWithLabelsFailsWhole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prepare func(*rig)
		status  int
		body    string
		logged  string
		keys    int
	}{
		{
			name: "the user is at the limit, or was revoked",
			prepare: func(rg *rig) {
				rg.store.failures[methodCreate] = errLimitRefusal
			},
			status: http.StatusConflict,
			body:   errorBody("agent_limit_reached", "an account may have at most 25 active agents"),
			logged: agents.CodeLimit, keys: 1,
		},
		{
			name: "the key cannot be issued", prepare: func(rg *rig) { rg.issueErr = errEntropy },
			status: http.StatusInternalServerError, body: bodyInternal, logged: agents.CodeKeyFailed, keys: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			tt.prepare(rg)

			rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, labelledBody(`["a","b"]`))

			wantFailure(t, rg, rec, tt.status, tt.body, tt.logged)

			if len(rg.issueCalls) != tt.keys {
				t.Errorf("issued %d keys, want %d", len(rg.issueCalls), tt.keys)
			}

			if len(rg.store.rows) != 0 {
				t.Errorf("a failed create left %+v", rg.store.rows)
			}
		})
	}
}

// labelDelegation is one create by an agent that holds agent:create, with labels,
// and what must come of it.
type labelDelegation struct {
	name string
	// creatorLabels are the labels the creating agent itself has.
	creatorLabels []string
	// creatorRevoked makes the creating agent revoked after its key was verified.
	creatorRevoked bool
	body           string
	status         int
	// shown is the response's labels, and written what reached the store.
	shown, written []string
}

func labelDelegations() []labelDelegation {
	const ok, conflict, malformed = http.StatusCreated, http.StatusConflict, http.StatusBadRequest

	return []labelDelegation{
		{"labels are the new agent's own", nil, false, labelledBody(`["worker","batch"]`), ok,
			strs("batch", "worker"), strs("worker", "batch")},
		{"the creator's labels are not inherited", strs("secret", "internal"), false, labelledBody(""), ok,
			strs(), strs()},
		{"the creator's labels are not merged in", strs("secret"), false, labelledBody(`["mine"]`), ok,
			strs("mine"), strs("mine")},
		{"the creator may give a label it has itself", strs("shared"), false, labelledBody(`["shared"]`), ok,
			strs("shared"), strs("shared")},
		{"a refused label creates nothing", nil, false, labelledBody(`["BAD"]`), malformed, nil, nil},
		{"a revoked creator creates nothing, labels included", nil, true, labelledBody(`["a"]`), conflict, nil, nil},
	}
}

// TestAnAgentCreatesAgentsWithLabels: labels are the owner's own bookkeeping and
// are not bounded by the creating agent the way scopes are. An agent that may
// create agents may give them any valid labels; they are written with the agent,
// the creator's own labels are neither copied nor changed, and a creator that
// was revoked in the meantime creates nothing, labels included.
func TestAnAgentCreatesAgentsWithLabels(t *testing.T) {
	t.Parallel()

	creator := scope.List{bundleAgent, agentCreate, agentRead}

	for _, tt := range labelDelegations() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var revokedAt *int64

			if tt.creatorRevoked {
				at := int64(5)
				revokedAt = &at
			}

			rg := newRig(t)
			rg.seed(userA, labelled(stored(agentA1, "creator", 1, revokedAt), tt.creatorLabels...))
			rg.store.rows[0].agent.Scopes = creator.JSON()

			rec := rg.withKey(agentCaller(rg, creator, creator), http.MethodPost, collection, tt.body)
			if rec.Code != tt.status {
				t.Fatalf("status = %d (%s), want %d", rec.Code, rec.Body, tt.status)
			}

			if tt.status != http.StatusCreated {
				if len(rg.store.rows) != 1 {
					t.Errorf("a refused create left %+v", rg.store.rows)
				}

				return
			}

			if got := created(t, rec.Body.Bytes()).Agent.Labels; !slices.Equal(got, tt.shown) {
				t.Errorf("labels = %v, want %v", got, tt.shown)
			}

			if got := writtenLabels(t, rg); !slices.Equal(got, tt.written) {
				t.Errorf("written = %v, want %v", got, tt.written)
			}

			// The creator's labels are exactly what they were.
			if got := rg.store.agent(t, agentA1).Labels; !slices.Equal(normalLabels(got), normalLabels(tt.creatorLabels)) {
				t.Errorf("the creating agent's labels = %v, want %v", got, tt.creatorLabels)
			}
		})
	}
}

// normalLabels is labels as a non-nil list, so that none and nil compare equal.
func normalLabels(labels []string) []string { return append([]string{}, labels...) }

// labelFilterOutcome is who lists what under one label filter.
type labelFilterOutcome struct {
	name, owner, query string
	status             int
	want               []string
}

func labelFilterOutcomes() []labelFilterOutcome {
	const ok = http.StatusOK

	return []labelFilterOutcome{
		{"the owner finds the new agent by its label", userA, "mine", ok, strs(newAgentID)},
		{"another user finds only their own agent", userB, "mine", ok, strs(agentB1)},
		{"a prefix of the label finds nothing", userA, "min", ok, strs()},
		{"a longer label finds nothing", userA, "mine2", ok, strs()},
		{"upper case is not a label", userA, "MINE", http.StatusBadRequest, nil},
	}
}

// TestCreateLabelsBelongToTheNewAgentAndItsOwner: a create's labels are written
// on the new agent for the caller's user and on no other, are found by exact
// match, and are not visible to another user.
func TestCreateLabelsBelongToTheNewAgentAndItsOwner(t *testing.T) {
	t.Parallel()

	for _, tt := range labelFilterOutcomes() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rg := newRig(t)
			rg.seed(userB, labelled(stored(agentB1, "theirs", 1, nil), "mine"))

			made := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, labelledBody(`["mine"]`))
			if made.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201: %s", made.Code, made.Body)
			}

			list := rg.as(rg.signIn(tt.owner, roleMember), http.MethodGet, collection+"?label="+tt.query, "")
			if list.Code != tt.status {
				t.Fatalf("label=%s = %d, want %d: %s", tt.query, list.Code, tt.status, list.Body)
			}

			if tt.want == nil {
				return
			}

			ids := make([]string, 0, len(tt.want))
			for _, agent := range listFrom(t, list).Agents {
				ids = append(ids, agent.ID)
			}

			if !slices.Equal(ids, tt.want) {
				t.Errorf("%s lists %v under label=%s, want %v", tt.owner, ids, tt.query, tt.want)
			}
		})
	}
}

// TestCreateThenPatchSharesTheLabelBound: a create with the most labels leaves an
// agent exactly at the limit, so the first PATCH that adds one more is the same
// 409 any agent at the limit gets, and one that swaps works.
func TestCreateThenPatchSharesTheLabelBound(t *testing.T) {
	t.Parallel()

	rg := newRig(t)
	full := labelsUpTo(input.MaxLabelsPerCreate)

	rec := rg.as(rg.signIn(userA, roleMember), http.MethodPost, collection, labelledBody(quotedLabels(full)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %.300s", rec.Code, rec.Body)
	}

	item := itemPrefix + newAgentID

	more := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, item, `{"addLabels":["extra"]}`)
	wantCode(t, rg, more, http.StatusConflict, agents.CodeLabelLimit)

	rg.logged = nil

	swap := rg.as(rg.signIn(userA, roleMember), http.MethodPatch, item,
		`{"addLabels":["extra"],"removeLabels":[`+jsonString(full[0])+`]}`)
	if swap.Code != http.StatusOK {
		t.Errorf("a swap at the limit = %d, want 200: %s", swap.Code, swap.Body)
	}
}
