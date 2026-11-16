package avscan

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestScanReaderNilReaderIsAnError(t *testing.T) {
	t.Parallel()
	dialled := false
	c := Clamd{Dial: func(context.Context) (net.Conn, error) {
		dialled = true
		return nil, errors.New("not dialled")
	}}
	if _, found, err := c.ScanReader(t.Context(), "x", nil); err == nil || found || errors.Is(err, ErrNoScanner) || dialled {
		t.Fatalf("nil reader = %v, %v, dialled %v; want a plain error and no dial", found, err, dialled)
	}
}

func TestScanOmitsErrNoScannerAfterVersion(t *testing.T) {
	n := 0
	c := Clamd{
		Dial: func(context.Context) (net.Conn, error) {
			n++
			if n > 1 {
				return nil, errors.New("clamd gone")
			}
			a, b := net.Pipe()
			go func() {
				defer func() { _ = b.Close() }()
				buf := make([]byte, 32)
				_, _ = b.Read(buf)
				_, _ = b.Write([]byte("ClamAV 1.4.0\x00"))
			}()
			return a, nil
		},
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := c.Scan(t.Context(), dir)
	if n < 2 {
		t.Fatalf("Version did not succeed (dial count %d, err %v)", n, err)
	}
	if err == nil {
		t.Fatal("expected error after daemon drop")
	}
	if errors.Is(err, ErrNoScanner) {
		t.Fatalf("Scan reported ErrNoScanner after Version: %v", err)
	}
}
