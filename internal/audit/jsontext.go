// The JSON forms appendRecord writes: strings with encoding/json's escaping
// (HTML characters, U+2028 and U+2029, invalid UTF-8 replaced by U+FFFD), numbers in
// its float form, RFC 3339 times, and the maps and lists of an Event.

package audit

import (
	"math"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"
)

const hexDigits = "0123456789abcdef"

// appendString appends s as a JSON string, escaped as encoding/json escapes
// it with HTML escaping on (its default).
func appendString(b []byte, s string) []byte {
	b = append(b, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != '"' && c != '\\' && c != '<' && c != '>' && c != '&' {
				i++
				continue
			}
			b = append(b, s[start:i]...)
			switch c {
			case '"', '\\':
				b = append(b, '\\', c)
			case '\b':
				b = append(b, '\\', 'b')
			case '\f':
				b = append(b, '\\', 'f')
			case '\n':
				b = append(b, '\\', 'n')
			case '\r':
				b = append(b, '\\', 'r')
			case '\t':
				b = append(b, '\\', 't')
			default:
				b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xF])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		// Invalid UTF-8 becomes U+FFFD itself; U+2028 and U+2029 are escaped,
		// as encoding/json does for JSONP safety.
		if r == utf8.RuneError && size == 1 {
			b = append(b, s[start:i]...)
			b = utf8.AppendRune(b, utf8.RuneError)
			i += size
			start = i
			continue
		}
		if r == 0x2028 || r == 0x2029 {
			b = append(b, s[start:i]...)
			b = append(b, '\\', 'u', '2', '0', '2', hexDigits[r&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	b = append(b, s[start:]...)
	return append(b, '"')
}

// appendFloat appends f in encoding/json's form: plain notation, or an
// exponent below 1e-6 and from 1e21, without a leading zero in it.
func appendFloat(b []byte, f float64) []byte {
	format := byte('f')
	if abs := math.Abs(f); abs != 0 && (abs < 1e-6 || abs >= 1e21) {
		format = 'e'
	}
	b = strconv.AppendFloat(b, f, format, -1, 64)
	if format == 'e' {
		// "e-09" becomes "e-9", as encoding/json writes it.
		if n := len(b); n >= 4 && b[n-4] == 'e' && b[n-3] == '-' && b[n-2] == '0' {
			b[n-2] = b[n-1]
			b = b[:n-1]
		}
	}
	return b
}

// appendTime appends t as time.Time's MarshalJSON writes it.
func appendTime(b []byte, t time.Time) []byte {
	b = append(b, '"')
	b = t.AppendFormat(b, time.RFC3339Nano)
	return append(b, '"')
}

// appendStrings appends a list of strings.
func appendStrings(b []byte, list []string) []byte {
	b = append(b, '[')
	for i, s := range list {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendString(b, s)
	}
	return append(b, ']')
}

// appendStringMap appends a map of strings, keys sorted as encoding/json sorts them.
func appendStringMap(b []byte, m map[string]string) []byte {
	b = append(b, '{')
	for i, k := range sortedKeys(m) {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendString(b, k)
		b = append(b, ':')
		b = appendString(b, m[k])
	}
	return append(b, '}')
}

// appendCountMap appends a map of counts, keys sorted.
func appendCountMap(b []byte, m map[string]uint64) []byte {
	b = append(b, '{')
	for i, k := range sortedKeys(m) {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendString(b, k)
		b = append(b, ':')
		b = strconv.AppendUint(b, m[k], 10)
	}
	return append(b, '}')
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// appendAddresses appends a summary's busiest addresses.
func appendAddresses(b []byte, list []AddressCount) []byte {
	b = append(b, '[')
	for i, a := range list {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, `{"address":`...)
		b = appendString(b, a.Address)
		b = append(b, `,"count":`...)
		b = strconv.AppendUint(b, a.Count, 10)
		b = append(b, '}')
	}
	return append(b, ']')
}
