// Package crontab edits the current user's crontab, touching only the lines
// devtools owns. Ownership is recorded with a trailing "# devtools:<name>"
// marker, so hand-written entries are never rewritten or removed.
package crontab

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

// Marker is the comment prefix that tags a devtools-managed line.
const Marker = "# devtools:"

// Entry is one managed crontab line.
type Entry struct {
	Name     string
	Schedule string
	Command  string
	Line     string // the raw line as it appears in the crontab
}

var markerRe = regexp.MustCompile(`#\s*devtools:([A-Za-z0-9._-]+)\s*$`)

// scheduleRe validates the five-field form plus the @reboot-style macros.
var (
	macroRe = regexp.MustCompile(`^@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)$`)
	fieldRe = regexp.MustCompile(`^[0-9*,/\-A-Za-z]+$`)
)

// ValidateSchedule checks a cron schedule well enough to catch typos before
// they become a silently broken crontab.
func ValidateSchedule(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("schedule is required (e.g. \"*/5 * * * *\" or \"@hourly\")")
	}
	if strings.HasPrefix(s, "@") {
		if !macroRe.MatchString(s) {
			return fmt.Errorf("unknown cron macro %q", s)
		}
		return nil
	}
	fields := strings.Fields(s)
	if len(fields) != 5 {
		return fmt.Errorf("cron schedule needs 5 fields (min hour dom mon dow), got %d in %q", len(fields), s)
	}
	for i, f := range fields {
		if !fieldRe.MatchString(f) {
			return fmt.Errorf("field %d (%q) has characters cron will not accept", i+1, f)
		}
	}
	return nil
}

// ValidateName checks a managed-entry name is marker-safe.
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9._-]+$`).MatchString(name) {
		return fmt.Errorf("name %q must be letters, digits, dot, dash or underscore", name)
	}
	return nil
}

// Read returns the raw crontab. An empty crontab is not an error.
func Read(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "crontab", "-l")
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		msg := errOut.String()
		// "no crontab for <user>" is the empty case, not a failure.
		if strings.Contains(msg, "no crontab for") {
			return "", nil
		}
		return "", fmt.Errorf("crontab -l: %w: %s", err, strings.TrimSpace(msg))
	}
	return out.String(), nil
}

// Write replaces the crontab wholesale.
func Write(ctx context.Context, content string) error {
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	cmd := exec.CommandContext(ctx, "crontab", "-")
	cmd.Stdin = strings.NewReader(content)
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("crontab -: %w: %s", err, strings.TrimSpace(errOut.String()))
	}
	return nil
}

// Parse extracts the devtools-managed entries from crontab text.
func Parse(content string) []Entry {
	var out []Entry
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := markerRe.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		body := strings.TrimSpace(markerRe.ReplaceAllString(trimmed, ""))
		schedule, command := splitSchedule(body)
		out = append(out, Entry{Name: m[1], Schedule: schedule, Command: command, Line: line})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// splitSchedule peels the schedule off the front of a cron line.
func splitSchedule(body string) (schedule, command string) {
	fields := strings.Fields(body)
	if len(fields) == 0 {
		return "", ""
	}
	n := 5
	if strings.HasPrefix(fields[0], "@") {
		n = 1
	}
	if len(fields) <= n {
		return strings.Join(fields, " "), ""
	}
	return strings.Join(fields[:n], " "), strings.Join(fields[n:], " ")
}

// List returns the managed entries currently installed.
func List(ctx context.Context) ([]Entry, error) {
	content, err := Read(ctx)
	if err != nil {
		return nil, err
	}
	return Parse(content), nil
}

// Render builds the full crontab line for a managed entry.
func Render(name, schedule, command string) string {
	return fmt.Sprintf("%s %s %s%s", strings.TrimSpace(schedule), strings.TrimSpace(command), Marker, name)
}

// Upsert adds or replaces the managed entry called name and returns the new
// crontab content. It does not write anything; callers decide that.
func Upsert(content, name, schedule, command string) string {
	newLine := Render(name, schedule, command)
	var out []string
	replaced := false
	for _, line := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		if m := markerRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil && m[1] == name {
			if !replaced {
				out = append(out, newLine)
				replaced = true
			}
			continue
		}
		out = append(out, line)
	}
	if !replaced {
		out = append(out, newLine)
	}
	return strings.TrimLeft(strings.Join(out, "\n"), "\n") + "\n"
}

// Remove drops the managed entry called name, reporting whether it existed.
func Remove(content, name string) (string, bool) {
	var out []string
	found := false
	for _, line := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		if m := markerRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil && m[1] == name {
			found = true
			continue
		}
		out = append(out, line)
	}
	joined := strings.TrimLeft(strings.Join(out, "\n"), "\n")
	if joined != "" {
		joined += "\n"
	}
	return joined, found
}
