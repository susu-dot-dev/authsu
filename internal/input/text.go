package input

// Bounds for the display-text types. Each is the Go-side limit; the schema
// CHECK it must fit inside is named on the constant.
const (
	// MaxAccountNameBytes bounds AccountName, in bytes. The name is stored in
	// users.profile as the JSON {"name": "..."}, which the CHECK
	// `length(profile) <= 1024` (migration 0001) limits to 1024 bytes. JSON
	// escaping can expand a character up to six-fold ("<" becomes \u003c), so
	// 128 bytes encode to at most 768 bytes plus the 10 bytes of the object
	// syntax, which leaves room for the other profile fields (MaxEmailBytes).
	MaxAccountNameBytes = 128

	// MaxAgentNameRunes bounds AgentName, in Unicode code points. The schema
	// CHECK `length(cast(name AS BLOB)) BETWEEN 1 AND 1024` (migration 0001)
	// counts bytes; 256 runes of at most 4 bytes each is exactly 1024.
	MaxAgentNameRunes = 256

	// MaxKeyNameRunes bounds KeyName, in Unicode code points. The schema CHECK
	// `length(cast(name AS BLOB)) BETWEEN 1 AND 1024` on api_keys.name
	// (migration 0001) counts bytes; 256 runes of at most 4 bytes each is
	// exactly 1024.
	MaxKeyNameRunes = 256

	// MaxInvitationLabelRunes bounds InvitationLabel, in Unicode code points.
	// The schema CHECK `length(cast(label AS BLOB)) <= 1024` on
	// invitations.label (migration 0001) counts bytes; 256 runes of at most 4
	// bytes each is exactly 1024. The CHECK also refuses NUL, which a label
	// never contains.
	MaxInvitationLabelRunes = 256

	// MaxOrgNameRunes bounds OrgName, in Unicode code points. The schema CHECK
	// `length(cast(name AS BLOB)) BETWEEN 1 AND 1024` on orgs.name
	// (migration 0001) counts bytes; 256 runes of at most 4 bytes each is
	// exactly 1024.
	MaxOrgNameRunes = 256
)

// Error codes of the display-text types.
const (
	CodeInvalidName      = "invalid_name"
	CodeInvalidAgentName = "invalid_agent_name"
	CodeInvalidKeyName   = "invalid_key_name"
	CodeInvalidOrgName   = "invalid_org_name"
	CodeInvalidLabel     = "invalid_label"
)

const (
	textRules            = " of normalised text without control or formatting characters"
	displayRules         = " of normalised text without control characters or hidden formatting"
	descInvalidName      = "name must be 1 to 128 bytes" + textRules
	descInvalidAgentName = "agent name must be 1 to 256 characters" + displayRules
	descInvalidKeyName   = "key name must be 1 to 256 characters" + displayRules
	descInvalidOrgName   = "organization name must be 1 to 256 characters" + displayRules
	descInvalidLabel     = "label must be at most 256 characters" + displayRules
)

// AccountName is the display name a person gives their account. It is what an
// administrator recognises an account by, and it is shown by the browser's
// passkey prompt, so it may not hide or reorder text: it admits no formatting
// character at all, joiners included.
//
// The other display text (AgentName, InvitationLabel) is not what anyone is
// identified by, and may hold the zero-width joiner and non-joiner so that emoji
// sequences and Persian, Indic and Sinhala text can be written. It still
// refuses controls, bidi controls, zero-width space and the other formatting
// characters, so it cannot reorder or hide text either.
type AccountName struct{ v string }

// ParseAccountName accepts display text of 1 to MaxAccountNameBytes bytes.
func ParseAccountName(raw string) (AccountName, error) {
	if !displayText(raw, textRule{unit: unitBytes, max: MaxAccountNameBytes, allowEmpty: false, identifying: true}) {
		return AccountName{}, refuse(CodeInvalidName, descInvalidName)
	}

	return AccountName{v: raw}, nil
}

// String returns the name exactly as it was parsed.
func (n AccountName) String() string { return n.v }

// AgentName is the label a user gives an agent to tell their agents apart.
type AgentName struct{ v string }

// ParseAgentName accepts display text of 1 to MaxAgentNameRunes runes.
func ParseAgentName(raw string) (AgentName, error) {
	if !displayText(raw, textRule{unit: unitRunes, max: MaxAgentNameRunes, allowEmpty: false, identifying: false}) {
		return AgentName{}, refuse(CodeInvalidAgentName, descInvalidAgentName)
	}

	return AgentName{v: raw}, nil
}

// String returns the name exactly as it was parsed.
func (n AgentName) String() string { return n.v }

// KeyName is the label a user gives an API key to tell their keys apart.
type KeyName struct{ v string }

// ParseKeyName accepts display text of 1 to MaxKeyNameRunes runes.
func ParseKeyName(raw string) (KeyName, error) {
	if !displayText(raw, textRule{unit: unitRunes, max: MaxKeyNameRunes, allowEmpty: false, identifying: false}) {
		return KeyName{}, refuse(CodeInvalidKeyName, descInvalidKeyName)
	}

	return KeyName{v: raw}, nil
}

// String returns the name exactly as it was parsed.
func (n KeyName) String() string { return n.v }

// OrgName is the name of an organization or a sandbox, which a person tells
// theirs apart by. Like AgentName it is not what anyone is identified by, so it
// may hold the joiners that some scripts need, and still refuses controls and
// hidden formatting.
type OrgName struct{ v string }

// ParseOrgName accepts display text of 1 to MaxOrgNameRunes runes.
func ParseOrgName(raw string) (OrgName, error) {
	if !displayText(raw, textRule{unit: unitRunes, max: MaxOrgNameRunes, allowEmpty: false, identifying: false}) {
		return OrgName{}, refuse(CodeInvalidOrgName, descInvalidOrgName)
	}

	return OrgName{v: raw}, nil
}

// String returns the name exactly as it was parsed.
func (n OrgName) String() string { return n.v }

// InvitationLabel is the note an administrator attaches to an invitation. It
// may be empty.
type InvitationLabel struct{ v string }

// ParseInvitationLabel accepts the empty string, or display text of up to
// MaxInvitationLabelRunes runes. Text that is only whitespace is refused.
func ParseInvitationLabel(raw string) (InvitationLabel, error) {
	if !displayText(raw, textRule{unit: unitRunes, max: MaxInvitationLabelRunes, allowEmpty: true, identifying: false}) {
		return InvitationLabel{}, refuse(CodeInvalidLabel, descInvalidLabel)
	}

	return InvitationLabel{v: raw}, nil
}

// String returns the label exactly as it was parsed.
func (l InvitationLabel) String() string { return l.v }
