package avscan

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

func TestCommandDetectionCodes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh")
	}
	dir := t.TempDir()

	t.Run("exit 1 with codes {1} is a detection", func(t *testing.T) {
		c := Command{Line: `sh -c "echo EICAR; exit 1" "{path}"`, DetectionCodes: []int{1}}
		d, found, err := c.Scan(t.Context(), dir)
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			t.Fatal("wanted detection")
		}
		if d.Name != "EICAR" {
			t.Fatalf("Name = %q", d.Name)
		}
	})

	t.Run("exit 2 is a ScanError", func(t *testing.T) {
		c := Command{Line: `sh -c "echo fail >&2; exit 2" "{path}"`, DetectionCodes: []int{1}}
		d, found, err := c.Scan(t.Context(), dir)
		if found {
			t.Fatalf("found detection %v", d)
		}
		var se ScanError
		if !errors.As(err, &se) {
			t.Fatalf("err = %v, want ScanError", err)
		}
		if se.ExitCode != 2 {
			t.Fatalf("ExitCode = %d", se.ExitCode)
		}
		if !strings.Contains(se.Stderr, "fail") {
			t.Fatalf("Stderr = %q", se.Stderr)
		}
	})

	t.Run("default non-zero is a detection", func(t *testing.T) {
		c := Command{Line: `sh -c "echo threat; exit 2" "{path}"`}
		d, found, err := c.Scan(t.Context(), dir)
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			t.Fatal("wanted detection")
		}
		if d.Name != "threat" {
			t.Fatalf("Name = %q", d.Name)
		}
	})
}
