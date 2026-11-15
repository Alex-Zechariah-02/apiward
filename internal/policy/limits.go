// Limits and identifier formats shared by policy decoding, compilation and the store.

package policy

// Each bound keeps the work and memory of one decode or one validation
// small and predictable; none is a setting, since no compared gateway
// exposes its JSON parser bounds and no register row shows one bites.
const (
	// MaxJSONDepth: deeper nesting than any API body or schema needs, and
	// the decoder's stack stays small.
	MaxJSONDepth = 16
	// MaxJSONValues: values per body or schema; bounds decoding and
	// validation work per request.
	MaxJSONValues = 4096
	// MaxNumberLength and maxExponentDigits: number literals the validator
	// compares exactly without arbitrary-precision cost.
	MaxNumberLength   = 32
	maxExponentDigits = 3
	// MaxSchemaProperties and MaxEnumValues: members a schema object may
	// list, which bounds each object's validation.
	MaxSchemaProperties = 64
	MaxEnumValues       = 64
	// MaxSchemaLength: the largest string length keyword; a longer string
	// could not fit in the largest body (MaxBodyLimit).
	MaxSchemaLength = MaxBodyLimit
	// MaxHeaderName: header names an operation may name; real names are
	// far shorter.
	MaxHeaderName = 64
)

// IsSubjectID accepts 1 to 128 printable ASCII characters without spaces. The
// same rule applies to the "sub" claim, so a subject identifier is always
// safe to log and to forward in a header.
func IsSubjectID(id string) bool {
	if id == "" || len(id) > MaxSubjectLength {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x21 || id[i] > 0x7e {
			return false
		}
	}
	return true
}

// CheckID accepts short identifiers made of letters, digits, '.', '_' and
// '-', starting with a letter or digit, so identifiers are safe to log and to
// compare byte for byte.
func CheckID(id, field string, args ...any) error {
	if id == "" || len(id) > MaxIDLength {
		return Invalid("INVALID_VALUE", field, args...)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		alphanumeric := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if alphanumeric {
			continue
		}
		if i == 0 || (c != '.' && c != '_' && c != '-') {
			return Invalid("INVALID_VALUE", field, args...)
		}
	}
	return nil
}

// Clip shortens untrusted text to 256 bytes, without splitting a UTF-8
// sequence, before it is echoed in a report or an error.
func Clip(text string) string {
	const limit = 256
	if len(text) <= limit {
		return text
	}
	cut := limit
	for cut > 0 && text[cut]&0xc0 == 0x80 {
		cut--
	}
	return text[:cut] + "…"
}
