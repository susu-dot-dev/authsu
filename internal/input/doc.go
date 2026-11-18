// Package input turns every value a client sends into a type that can only
// exist if it was valid.
//
// # The pattern
//
// Parse, don't validate. A handler never holds a raw string and a separate
// promise that somebody checked it. It calls a parser (ParseAgentName,
// ParseID, ...) once, at the boundary, and from then on passes the typed
// result. Each type is a struct with an unexported field, never `type X
// string`: a conversion such as AgentName("x") would compile and bypass the
// parser, whereas a struct literal from another package cannot name the field.
// The one value other code can still build is the zero value of a type
// (AgentName{} is empty, a value its parser refuses). The zero value
// cannot be told apart from a parsed one by the type system, so code that
// builds it by mistake is a defect, not an input.
//
// # Refuse, never rewrite
//
// A parser never trims, case-folds, normalises or truncates. It accepts the
// canonical spelling and refuses everything else. The consequence is that one
// stored value has exactly one client spelling: an upper-case UUID is not an
// alias for a lower-case one, a name in NFD is refused rather than silently
// converted to NFC, and "007" is not a spelling of 7. Silent rewriting is how
// two layers end up disagreeing about what was stored, and how a lookup by
// the "same" value misses.
//
// # Errors
//
// Every parser returns an *apierr.Error of kind BadRequest that carries the
// type's code (CodeInvalidID, ...). The description is fixed, names the rule
// rather than the offending value, and never echoes the input, so it is safe to
// show a client and cannot reflect attacker-controlled text into a response or
// a log line. Callers return the error unchanged.
//
// # Bounds mirror the schema
//
// Every size is an exported constant beside its type, in the unit the schema
// measures it in, and each comment names the migration CHECK it must fit
// inside. The Go bound is the tighter one: the CHECK is a last-line backstop
// and a request that reaches it is a defect. Where the client-facing unit
// (characters) differs from the schema's (bytes), the constant is chosen so the
// worst case still fits: 256 runes of at most 4 bytes each is exactly the 1024
// bytes the agents table allows.
//
// # Integers stay at or below 2^53-1
//
// D1 moves numbers between Go and SQLite through JavaScript, where every
// number is a float64. An integer above MaxSafeInteger (2^53-1) loses
// precision in both directions, so a stored value could differ from the one
// that was checked. Every integer type here is bounded far below that
// (counts are thousands, timestamps are Unix seconds a decade ahead), and
// ParseExpiry additionally refuses anything above MaxSafeInteger whatever the
// clock says.
//
// # What is not an input
//
// Values the server generates (ids, timestamps, invitation codes it issues,
// signing keys) are not parsed here and stay plain types: they are correct by
// construction, and wrapping them would only rename them. The one exception
// is a generated value coming back from a client: an id in a URL or a cursor
// is an input and is parsed as an ID, however it was originally generated.
package input
