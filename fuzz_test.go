package avscan

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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

// Command stdout is untrusted: the detection name is short, valid UTF-8 and free of control characters.
func FuzzFirstLine(f *testing.F) {
	for _, seed := range []string{
		"Win.Test.Bad",
		"",
		"  Win.Bad\x1b[31m\r\n ",
		strings.Repeat("0", 300),
		"\n\nWin.Test\nsecond",
		"\xff\xfe",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		name := firstLine(s)
		if len(name) > maxNameLen || !utf8.ValidString(name) {
			t.Fatalf("name %q is too long or not UTF-8", name)
		}
		if strings.IndexFunc(name, unicode.IsControl) >= 0 {
			t.Fatalf("name %q carries a control character", name)
		}
	})
}

// A clamd VERSION reply is untrusted: only a "ClamAV " prefix is accepted, and the string cannot grow past the read cap.
func FuzzClamdVersion(f *testing.F) {
	for _, seed := range []string{
		"ClamAV 1.4.0\x00",
		"ClamAV 1.0.1/26900/Mon Jan  1 00:00:00 2024\x00",
		"not clamd\x00",
		"",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, reply []byte) {
		if len(reply) > 8192 {
			reply = reply[:8192]
		}
		client, server := net.Pipe()
		defer func() { _ = client.Close() }()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() { _ = server.Close() }()
			buf := make([]byte, 32)
			_, _ = server.Read(buf)
			_, _ = server.Write(reply)
		}()
		//nolint:usetesting // ClusterFuzzLite builds fuzz targets against a testing.T with no Context method.
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		ver, err := (Clamd{Dial: func(context.Context) (net.Conn, error) { return client, nil }}).Version(ctx)
		<-done
		if err != nil && ver != "" {
			t.Fatalf("version %q with error %v", ver, err)
		}
		if err == nil && !strings.HasPrefix(ver, "ClamAV ") {
			t.Fatalf("accepted %q", ver)
		}
		if len(ver) > 4096 {
			t.Fatalf("unbounded version length %d", len(ver))
		}
	})
}

// A relative path handed to openRegular cannot name a file outside the root.
func FuzzOpenRegular(f *testing.F) {
	dir := f.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "a"), 0o700); err != nil {
		f.Fatal(err)
	}
	for _, name := range []string{"inside.txt", filepath.Join("a", "b")} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			f.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = root.Close() })
	rootDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		f.Fatal(err)
	}

	for _, seed := range []string{"inside.txt", "a/b", "../inside.txt", "..", "/", "", "a/../inside.txt"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, rel string) {
		file, err := openRegular(root, rel)
		if err != nil {
			return
		}
		defer func() { _ = file.Close() }()
		got, err := filepath.EvalSymlinks(file.Name())
		if err != nil {
			t.Fatal(err)
		}
		escaped, err := filepath.Rel(rootDir, got)
		if err != nil || escaped == ".." || strings.HasPrefix(escaped, ".."+string(os.PathSeparator)) {
			t.Fatalf("opened %q via %q, outside %q", got, rel, rootDir)
		}
	})
}
