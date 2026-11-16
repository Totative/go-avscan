package avscan

import (
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// A clamd reply is untrusted: whatever it says, the detection name reaching the caller is short, valid UTF-8 and
// free of control characters.
func FuzzParseReply(f *testing.F) {
	for _, seed := range []string{
		"stream: OK\x00",
		"stream: Eicar-Test-Signature FOUND\x00",
		"INSTREAM size limit exceeded. ERROR\x00",
		"stream: \x1b[31mred\x07 FOUND\x00",
		"",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, reply []byte) {
		name, err := parseReply(strings.NewReader(string(reply)))
		if err != nil && name != "" {
			t.Fatalf("name %q returned with error %v", name, err)
		}
		if len(name) > maxNameLen || !utf8.ValidString(name) {
			t.Fatalf("name %q is too long or not UTF-8", name)
		}
		if strings.IndexFunc(name, unicode.IsControl) >= 0 {
			t.Fatalf("name %q carries a control character", name)
		}
	})
}

// Quotes only group: a line holding neither quote splits exactly on spaces and tabs.
func FuzzSplitCommand(f *testing.F) {
	for _, seed := range []string{`clamscan --no-summary "{path}"`, `"C:\Program Files\av\scan.exe" --quiet`, `a  "b c`, `'a "b' c`, ``} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		parts, err := splitCommand(line)
		if strings.ContainsAny(line, `"'`) {
			return
		}
		if err != nil {
			t.Fatalf("split %q without a quote = %v", line, err)
		}
		if want := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' }); !slices.Equal(parts, want) {
			t.Fatalf("split %q = %q, want %q", line, parts, want)
		}
	})
}
