package avscan

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Rethunk-Tech/go-desktopenv/nowindow"
)

// Command runs a scanner program the caller names. Line is split on spaces and tabs with no shell; a single- or
// double-quoted part stays whole, with the quotes removed and the other quote literal inside it, and "{path}" in any
// part is replaced by the folder. Exit 0 is clean. DetectionCodes lists the exit codes that mean a detection whose
// name is the first non-empty line of stdout ("" when stdout is empty); when DetectionCodes is empty, any non-zero
// exit is a detection, so callers that treated every non-zero as infected keep that behaviour. Any other non-zero
// exit is a [ScanError] with that code and stderr. A program that does not start is an error, one killed by a signal
// is an error, an empty Line is [ErrNoScanner], a Line without "{path}" is refused since the program would never be
// given the folder, and a Line with an unterminated quote is an error rather than a guess at the argv.
type Command struct {
	Line           string
	DetectionCodes []int
}

// ScanError is a command that exited with a code that is not a detection.
type ScanError struct {
	ExitCode int
	Stderr   string
}

func (e ScanError) Error() string {
	if s := strings.TrimSpace(e.Stderr); s != "" {
		return fmt.Sprintf("avscan: scanner exit %d: %s", e.ExitCode, s)
	}
	return fmt.Sprintf("avscan: scanner exit %d", e.ExitCode)
}

// splitCommand splits a command line on spaces, keeping a quoted part whole. Either quote opens a part; the other
// quote is literal inside it, so a path in single quotes survives a shell-free split unharmed.
func splitCommand(line string) ([]string, error) {
	var out []string
	var cur strings.Builder
	var quote byte
	started := false
	// Bytes, not runes: every delimiter is ASCII, and ranging over runes would rewrite invalid UTF-8 as U+FFFD.
	for i := range len(line) {
		r := line[i]
		switch {
		case quote != 0:
			started = true
			if r == quote {
				quote = 0
				continue
			}
			cur.WriteByte(r)
		case r == '"' || r == '\'':
			quote, started = r, true
		case r == ' ' || r == '\t':
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteByte(r)
			started = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("avscan: unterminated %q in command line", quote)
	}
	if started {
		out = append(out, cur.String())
	}
	return out, nil
}

// Program is the base name of the command's first part, "" when Line is empty or cannot be split.
func (c Command) Program() string {
	parts, err := splitCommand(c.Line)
	if err != nil || len(parts) == 0 {
		return ""
	}
	return filepath.Base(parts[0])
}

// errNoPathInLine refuses a command line that would never be given the folder.
var errNoPathInLine = errors.New("avscan: command line has no {path}")

// commandWaitDelay is how long a cancelled scan waits for the scanner's leftover children to close its output.
const commandWaitDelay = 2 * time.Second

// Scan runs the command once for the whole folder; File of a detection is "" because a command does not say which
// file it flagged.
func (c Command) Scan(ctx context.Context, dir string) (Detection, bool, error) {
	parts, err := splitCommand(c.Line)
	if err != nil {
		return Detection{}, false, err
	}
	if len(parts) == 0 {
		return Detection{}, false, ErrNoScanner
	}
	// Without {path} the program never learns which folder to scan, and its exit 0 would read as this folder clean.
	if !strings.Contains(c.Line, "{path}") {
		return Detection{}, false, errNoPathInLine
	}
	for i, p := range parts {
		parts[i] = strings.ReplaceAll(p, "{path}", dir)
	}
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...) //nolint:gosec // G204: argv is the caller's configured scanner command with {path} substituted
	nowindow.Set(cmd)
	// A scanner can leave a child holding stdout open after it is killed; WaitDelay ends the wait for it.
	cmd.WaitDelay = commandWaitDelay
	var out, stderr cappedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err == nil {
		return Detection{}, false, nil
	}
	if ctx.Err() != nil {
		return Detection{}, false, ctx.Err()
	}
	if ee, exited := errors.AsType[*exec.ExitError](err); exited {
		if ee.ExitCode() == -1 {
			return Detection{}, false, fmt.Errorf("run %s: %w", parts[0], err)
		}
		if !c.detected(ee.ExitCode()) {
			return Detection{}, false, ScanError{ExitCode: ee.ExitCode(), Stderr: stderr.String()}
		}
		return Detection{Name: firstLine(out.String()), Scanner: filepath.Base(parts[0])}, true, nil
	}
	return Detection{}, false, fmt.Errorf("run %s: %w", parts[0], err)
}

func (c Command) detected(code int) bool {
	return len(c.DetectionCodes) == 0 || slices.Contains(c.DetectionCodes, code)
}

func firstLine(s string) string {
	for line := range strings.SplitSeq(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return cleanName(line)
		}
	}
	return ""
}

// commandOutputCap is how much of a scanner's output is kept: the name comes from its first line, and a scanner that
// prints without end must not fill memory.
const commandOutputCap = 64 << 10

// cappedBuffer keeps the first commandOutputCap bytes written and discards the rest, still reporting every write as
// taken so the program is not blocked on a full pipe.
type cappedBuffer struct{ b []byte }

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := commandOutputCap - len(c.b); room > 0 {
		c.b = append(c.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return string(c.b) }
