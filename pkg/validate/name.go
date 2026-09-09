// Package validate holds shared input checks for agent-supplied identifiers.
package validate

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaxNameLength is the longest accepted name, in characters.
const MaxNameLength = 50

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Name trims value and rejects it if empty, longer than MaxNameLength, or
// containing anything outside [a-zA-Z0-9_-]. It returns the trimmed value.
func Name(field, value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("%s is required", field)
	}
	if n := utf8.RuneCountInString(trimmed); n > MaxNameLength {
		return "", fmt.Errorf("%s must be at most %d characters, got %d", field, MaxNameLength, n)
	}
	if !namePattern.MatchString(trimmed) {
		return "", fmt.Errorf("%s must match %s", field, namePattern.String())
	}
	return trimmed, nil
}

// SanitizeName coerces value into a valid Name: first dot-separated label,
// unsupported runs collapsed to "-", dashes trimmed, truncated to
// MaxNameLength. Returns "" when nothing usable remains.
func SanitizeName(value string) string {
	label := strings.TrimSpace(value)
	if i := strings.Index(label, "."); i > 0 {
		label = label[:i]
	}

	var b strings.Builder
	lastDash := false
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
			lastDash = r == '-'
		default:
			if b.Len() > 0 && !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}

	out := strings.Trim(b.String(), "-")
	if len(out) > MaxNameLength {
		out = strings.Trim(out[:MaxNameLength], "-")
	}
	return out
}
