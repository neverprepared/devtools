// Package check is the shared assertion and reporting engine for the diagnostic
// commands (web, dns, tls). It exists so every such command renders the same
// way, speaks the same --json shape, and agrees on what an exit code means.
package check

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Status is the outcome of one step or assertion.
type Status string

const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
	Skip Status = "skip"
)

// severity orders statuses so Worst can pick the most serious one.
func (s Status) severity() int {
	switch s {
	case Fail:
		return 3
	case Warn:
		return 2
	case Pass:
		return 1
	default: // Skip
		return 0
	}
}

// Label is the fixed-width marker printed in text output.
func (s Status) Label() string {
	switch s {
	case Pass:
		return "ok"
	case Warn:
		return "warn"
	case Fail:
		return "FAIL"
	default:
		return "skip"
	}
}

// Result is one line of a report: a named step or assertion, its outcome, and
// whatever detail a human needs to act on it.
type Result struct {
	Name      string   `json:"name"`
	Status    Status   `json:"status"`
	Detail    string   `json:"detail,omitempty"`
	Notes     []string `json:"notes,omitempty"`
	ElapsedMS float64  `json:"elapsed_ms,omitempty"`
}

// Elapsed records how long a step took.
func (r Result) Elapsed(d time.Duration) Result {
	r.ElapsedMS = float64(d.Microseconds()) / 1000
	return r
}

// Note attaches a sub-line to a result.
func (r Result) Note(format string, args ...any) Result {
	r.Notes = append(r.Notes, fmt.Sprintf(format, args...))
	return r
}

// Convenience constructors, used as check.OK("dns", "...").
func OK(name, format string, args ...any) Result {
	return Result{Name: name, Status: Pass, Detail: fmt.Sprintf(format, args...)}
}
func Warnf(name, format string, args ...any) Result {
	return Result{Name: name, Status: Warn, Detail: fmt.Sprintf(format, args...)}
}
func Failf(name, format string, args ...any) Result {
	return Result{Name: name, Status: Fail, Detail: fmt.Sprintf(format, args...)}
}
func Skipf(name, format string, args ...any) Result {
	return Result{Name: name, Status: Skip, Detail: fmt.Sprintf(format, args...)}
}

// Timing is the per-phase breakdown of a request, in milliseconds.
type Timing struct {
	DNSMS     float64 `json:"dns_ms,omitempty"`
	ConnectMS float64 `json:"connect_ms,omitempty"`
	TLSMS     float64 `json:"tls_ms,omitempty"`
	TTFBMS    float64 `json:"ttfb_ms,omitempty"`
	TotalMS   float64 `json:"total_ms,omitempty"`
}

// Report is the full outcome of one check run.
type Report struct {
	Command   string         `json:"command"`
	Target    string         `json:"target"`
	StartedAt time.Time      `json:"started_at"`
	Steps     []Result       `json:"steps"`
	Timing    *Timing        `json:"timing,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
	Summary   Status         `json:"summary"`
	ExitCode  int            `json:"exit_code"`
}

// NewReport starts a report for a target.
func NewReport(command, target string) *Report {
	return &Report{
		Command:   command,
		Target:    target,
		StartedAt: time.Now(),
		Data:      map[string]any{},
	}
}

// Add appends a result and returns it, so callers can branch on the status they
// just recorded.
func (r *Report) Add(res Result) Status {
	r.Steps = append(r.Steps, res)
	return res.Status
}

// Set stores structured phase detail for --json consumers.
func (r *Report) Set(key string, value any) {
	if r.Data == nil {
		r.Data = map[string]any{}
	}
	r.Data[key] = value
}

// Worst returns the most serious status in the report. A report of nothing
// but skipped steps summarises as Skip, not Pass: nothing was actually proven.
func (r *Report) Worst() Status {
	if len(r.Steps) == 0 {
		return Pass
	}
	worst := r.Steps[0].Status
	for _, s := range r.Steps[1:] {
		if s.Status.severity() > worst.severity() {
			worst = s.Status
		}
	}
	return worst
}

// Exit codes. These are the contract for launchd agents and cron entries:
// only 0 means "nothing to look at".
const (
	ExitOK       = 0
	ExitFailed   = 2 // a step or assertion failed
	ExitWarnings = 3 // warnings only, and --strict was set
)

// Finalize computes the summary status and exit code. With strict, warnings
// are treated as failures worth waking someone up for.
func (r *Report) Finalize(strict bool) int {
	r.Summary = r.Worst()
	switch {
	case r.Summary == Fail:
		r.ExitCode = ExitFailed
	case r.Summary == Warn && strict:
		r.ExitCode = ExitWarnings
	default:
		r.ExitCode = ExitOK
	}
	return r.ExitCode
}

// RenderJSON writes the machine-readable form.
func (r *Report) RenderJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// RenderText writes the human-readable form: one aligned line per step, the
// timing breakdown, then a summary.
func (r *Report) RenderText(w io.Writer) {
	fmt.Fprintf(w, "%s  %s\n\n", strings.ToUpper(r.Command), r.Target)

	width := 0
	for _, s := range r.Steps {
		if len(s.Name) > width {
			width = len(s.Name)
		}
	}

	for _, s := range r.Steps {
		took := ""
		if s.ElapsedMS > 0 {
			took = "  " + formatMS(s.ElapsedMS)
		}
		fmt.Fprintf(w, "%-4s  %-*s  %s%s\n", s.Status.Label(), width, s.Name, s.Detail, took)
		for _, n := range s.Notes {
			fmt.Fprintf(w, "      %-*s  %s\n", width, "", n)
		}
	}

	if t := r.Timing; t != nil {
		var parts []string
		for _, p := range []struct {
			name string
			ms   float64
		}{
			{"dns", t.DNSMS}, {"connect", t.ConnectMS}, {"tls", t.TLSMS},
			{"ttfb", t.TTFBMS}, {"total", t.TotalMS},
		} {
			if p.ms > 0 {
				parts = append(parts, fmt.Sprintf("%s %s", p.name, formatMS(p.ms)))
			}
		}
		if len(parts) > 0 {
			fmt.Fprintf(w, "\ntiming  %s\n", strings.Join(parts, "   "))
		}
	}

	counts := map[Status]int{}
	for _, s := range r.Steps {
		counts[s.Status]++
	}
	var summary []string
	for _, st := range []Status{Pass, Warn, Fail, Skip} {
		if counts[st] > 0 {
			summary = append(summary, fmt.Sprintf("%d %s", counts[st], st))
		}
	}
	fmt.Fprintf(w, "\n%s: %s\n", strings.ToUpper(string(r.Summary)), strings.Join(summary, ", "))
}

// formatMS prints a duration the way a human scans it.
func formatMS(ms float64) string {
	switch {
	case ms >= 10000:
		return fmt.Sprintf("%.1fs", ms/1000)
	case ms >= 1000:
		return fmt.Sprintf("%.2fs", ms/1000)
	case ms >= 10:
		return fmt.Sprintf("%.0fms", ms)
	default:
		return fmt.Sprintf("%.1fms", ms)
	}
}

// SortedKeys is a small helper for deterministic rendering of maps.
func SortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
