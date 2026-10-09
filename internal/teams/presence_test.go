package teams

import (
	"strings"
	"testing"
	"time"
)

func TestResolve(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"away", "away"},
		{"AWAY", "away"},
		{" active ", "available"},
		{"/dnd", "dnd"},
		{"do-not-disturb", "dnd"},
		{"invisible", "offline"},
	} {
		got, err := Resolve(tc.in)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", tc.in, err)
		}
		if got.Name != tc.want {
			t.Errorf("Resolve(%q) = %q, want %q", tc.in, got.Name, tc.want)
		}
	}
	if _, err := Resolve("lunch"); err == nil {
		t.Error("Resolve(\"lunch\") should fail")
	}
}

func TestSecs(t *testing.T) {
	for _, tc := range []struct {
		in   time.Duration
		want string
	}{
		{500 * time.Millisecond, "0.5"},
		{200 * time.Millisecond, "0.2"},
		{2 * time.Second, "2"},
		{0, "0"},
		{-time.Second, "0"},
	} {
		if got := secs(tc.in); got != tc.want {
			t.Errorf("secs(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestScript(t *testing.T) {
	st, _ := Resolve("away")
	got := Script(st, DefaultOptions(), "")

	for _, want := range []string{
		`tell application "Microsoft Teams" to activate`,
		"delay 0.5",
		`keystroke "e" using {command down}`,
		`keystroke "/away"`,
		"key code 36",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("script missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "try") {
		t.Error("no restore app was given, so the script should not restore focus")
	}
}

func TestScriptRestoresFocus(t *testing.T) {
	st, _ := Resolve("busy")
	got := Script(st, DefaultOptions(), "Ghostty")
	if !strings.Contains(got, `tell application "Ghostty" to activate`) {
		t.Errorf("script should restore focus:\n%s", got)
	}

	// Restoring focus to Teams itself would be a no-op; skip it.
	same := Script(st, DefaultOptions(), DefaultApp)
	if strings.Count(same, "to activate") != 1 {
		t.Errorf("should not re-activate Teams:\n%s", same)
	}
}

func TestScriptQuotesAppName(t *testing.T) {
	st, _ := Resolve("away")
	opts := DefaultOptions()
	opts.App = `Weird "App"`
	got := Script(st, opts, "")
	if !strings.Contains(got, `tell application "Weird \"App\"" to activate`) {
		t.Errorf("app name not escaped:\n%s", got)
	}
}
