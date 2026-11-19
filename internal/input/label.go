package input

// Bounds of the label types.
const (
	// MaxLabelBytes bounds Label, in bytes. The alphabet is ASCII, so bytes and
	// characters are the same. The schema CHECK
	// `length(cast(label AS BLOB)) BETWEEN 1 AND 63` (migration 0001) counts
	// bytes and allows exactly this.
	MaxLabelBytes = 63

	// MaxLabelsPerAgent bounds how many labels one agent may have. It is
	// enforced by the write that adds a label (a count in the statement, not a
	// read before it), and no schema CHECK can state it.
	MaxLabelsPerAgent = 20

	// MaxLabelsPerPatch bounds how many labels one request may add, and how
	// many it may remove. It keeps the batch a request writes small, and it is
	// the `maxitems` of the PATCH body's arrays, so an oversized array is
	// refused before it is decoded in full. It equals MaxLabelsPerAgent: a
	// request that adds more than an agent may hold could not succeed anyway.
	MaxLabelsPerPatch = MaxLabelsPerAgent

	// MaxLabelsPerCreate bounds how many labels a create may give the new
	// agent. A new agent has none, so the bound is the most an agent may have,
	// which is also the `maxitems` of the create body's array.
	MaxLabelsPerCreate = MaxLabelsPerAgent
)

// Error codes of the label types.
const (
	CodeInvalidLabelName   = "invalid_agent_label"
	CodeInvalidLabelFilter = "invalid_label_filter"
	CodeInvalidLabelPatch  = "invalid_label_patch"
	CodeInvalidLabelSet    = "invalid_label_set"
)

const (
	descInvalidLabelName = "label must be 1 to 63 characters, each a lower-case letter, a digit, '.', '_' or '-'"
	descInvalidFilter    = "label must be given at most once, as 1 to 63 characters, each a lower-case letter, " +
		"a digit, '.', '_' or '-'"
	descInvalidPatch = "a label may be added or removed, not both, and not twice"
	descInvalidSet   = "labels must be at most 20 in number, and none may be given twice"
)

// isLabelByte reports whether c may appear in a label: [a-z0-9._-]. The
// alphabet is deliberately narrow. A label is looked up by exact match, so it
// has no case to fold, no normalisation form to agree on and no hidden or
// reordering character to refuse, and every layer (JSON, Go, JavaScript, SQLite
// BINARY collation) compares the same bytes.
func isLabelByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
}

// validLabel reports whether s is 1 to MaxLabelBytes bytes of the label
// alphabet. The length is checked first, so an overlong string is refused
// without being scanned.
func validLabel(s string) bool {
	return s != "" && len(s) <= MaxLabelBytes && onlyBytes(s, isLabelByte)
}

// Label is a tag a user attaches to one of their agents.
type Label struct{ v string }

// ParseLabel accepts 1 to MaxLabelBytes bytes of [a-z0-9._-]. It refuses, and
// never corrects: "Prod" is not an alias for "prod".
func ParseLabel(raw string) (Label, error) {
	if !validLabel(raw) {
		return Label{}, refuse(CodeInvalidLabelName, descInvalidLabelName)
	}

	return Label{v: raw}, nil
}

// String returns the label exactly as it was parsed.
func (l Label) String() string { return l.v }

// LabelFilter is the label a list request asks for, or nothing for no filter.
type LabelFilter struct {
	label Label
	set   bool
}

// ParseLabelFilter reads the values of the "label" query parameter. No values
// mean no filter. Otherwise there must be exactly one value, a Label: a
// repeated parameter is refused, not read as "any of" or "all of", because
// which one a layer would pick (first, last, both) differs and a request must
// not mean two things. A present but empty value is refused, not treated as
// absent.
func ParseLabelFilter(values []string) (LabelFilter, error) {
	raw, present, single := singleValue(values)
	if !single || (present && !validLabel(raw)) {
		return LabelFilter{}, refuse(CodeInvalidLabelFilter, descInvalidFilter)
	}

	if !present {
		return LabelFilter{}, nil
	}

	return LabelFilter{label: Label{v: raw}, set: true}, nil
}

// Label returns the label to filter by, and false when there is no filter.
func (f LabelFilter) Label() (Label, bool) { return f.label, f.set }

// LabelPatch is a change to an agent's labels: labels to add and labels to
// remove. A label is never in both and never repeated within one, so the order
// the two lists are applied in cannot change the outcome, and no label means
// two things in one request. It may be empty.
type LabelPatch struct {
	add    []Label
	remove []Label
}

// ParseLabelPatch parses the two lists of a PATCH body. It refuses a label that
// is invalid, one that appears twice in a list, and one that is in both lists.
// Each list holds at most MaxLabelsPerPatch labels; the body decoder enforces
// that before this runs, and it is checked here too, because a caller that
// builds a patch some other way must not be able to exceed it.
func ParseLabelPatch(add, remove []string) (LabelPatch, error) {
	if len(add) > MaxLabelsPerPatch || len(remove) > MaxLabelsPerPatch {
		return LabelPatch{}, refuse(CodeInvalidLabelPatch, descInvalidPatch)
	}

	seen := make(map[string]struct{}, len(add)+len(remove))

	adds, err := parseLabelList(add, seen, repeated{CodeInvalidLabelPatch, descInvalidPatch})
	if err != nil {
		return LabelPatch{}, err
	}

	removes, err := parseLabelList(remove, seen, repeated{CodeInvalidLabelPatch, descInvalidPatch})
	if err != nil {
		return LabelPatch{}, err
	}

	return LabelPatch{add: adds, remove: removes}, nil
}

// repeated is the refusal of a label that is given twice: each request kind has
// its own code and description for it.
type repeated struct{ code, description string }

// parseLabelList parses raw into labels, recording each in seen and refusing one
// that seen already holds with again.
func parseLabelList(raw []string, seen map[string]struct{}, again repeated) ([]Label, error) {
	labels := make([]Label, 0, len(raw))

	for _, text := range raw {
		label, err := ParseLabel(text)
		if err != nil {
			return nil, err
		}

		if _, dup := seen[text]; dup {
			return nil, refuse(again.code, again.description)
		}

		seen[text] = struct{}{}

		labels = append(labels, label)
	}

	return labels, nil
}

// Add returns the labels to add, in the order sent. The slice is a copy.
func (p LabelPatch) Add() []Label { return append([]Label(nil), p.add...) }

// Remove returns the labels to remove, in the order sent. The slice is a copy.
func (p LabelPatch) Remove() []Label { return append([]Label(nil), p.remove...) }

// Empty reports whether the patch changes nothing.
func (p LabelPatch) Empty() bool { return len(p.add) == 0 && len(p.remove) == 0 }

// LabelSet is the labels a new agent is created with: at most
// MaxLabelsPerCreate, none repeated. It may be empty, which is how an agent
// created without labels is described.
type LabelSet struct {
	labels []Label
}

// ParseLabelSet parses the labels of a create body. It refuses a label that is
// invalid, one given twice, and more than MaxLabelsPerCreate of them. The body
// decoder enforces the count before this runs; it is checked here too, because
// a caller that builds a set some other way must not be able to exceed it.
//
// A repeated label is refused and not collapsed, as for a patch: a request must
// not say one thing twice, and a client that does has a defect to learn about.
func ParseLabelSet(raw []string) (LabelSet, error) {
	if len(raw) > MaxLabelsPerCreate {
		return LabelSet{}, refuse(CodeInvalidLabelSet, descInvalidSet)
	}

	labels, err := parseLabelList(raw, make(map[string]struct{}, len(raw)), repeated{CodeInvalidLabelSet, descInvalidSet})
	if err != nil {
		return LabelSet{}, err
	}

	// No labels is always the zero LabelSet, whether the list was absent or
	// empty, so two sets that mean the same compare equal.
	if len(labels) == 0 {
		return LabelSet{}, nil
	}

	return LabelSet{labels: labels}, nil
}

// Labels returns the labels, in the order sent. The slice is a copy.
func (s LabelSet) Labels() []Label { return append([]Label(nil), s.labels...) }

// Empty reports whether there are no labels.
func (s LabelSet) Empty() bool { return len(s.labels) == 0 }
