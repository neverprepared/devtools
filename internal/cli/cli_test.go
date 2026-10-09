package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neverprepared/devtools/internal/check"
)

// run executes the command tree with args and returns combined output.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	g = globals{} // the flag struct is package-level; keep tests independent
	var buf bytes.Buffer
	root := NewRootCmd()
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return buf.String(), err
}

func TestTeamsAppleScriptDryRunPrintsScript(t *testing.T) {
	out, err := run(t, "teams", "away", "--dry-run", "--via", "applescript")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`keystroke "/away"`, "key code 36"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestTeamsAliasSubcommand(t *testing.T) {
	// "active" is an alias of the available subcommand.
	out, err := run(t, "teams", "active", "-n", "--via", "applescript")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `keystroke "/available"`) {
		t.Errorf("alias did not resolve:\n%s", out)
	}
}

func TestTeamsDelayFlagsReachTheScript(t *testing.T) {
	out, err := run(t, "teams", "busy", "-n", "--via", "applescript", "--activate-delay", "1.5s", "--key-delay", "300ms")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "delay 1.5") || !strings.Contains(out, "delay 0.3") {
		t.Errorf("delay flags not applied:\n%s", out)
	}
}

func TestTeamsGraphDryRunPrintsRequest(t *testing.T) {
	// Graph is the default transport, so no --via is needed here.
	out, err := run(t, "teams", "dnd", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"POST /users/",
		"presence/setUserPreferredPresence",
		`"availability": "DoNotDisturb"`,
		`"activity": "DoNotDisturb"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// No expiration was requested, so Graph's own default should apply.
	if strings.Contains(out, "expirationDuration") {
		t.Errorf("expirationDuration should be omitted when no hold is given:\n%s", out)
	}
}

func TestTeamsGraphOfflineMapsToOffWork(t *testing.T) {
	// The one status whose Graph activity differs from its availability.
	out, err := run(t, "teams", "offline", "-n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"availability": "Offline"`) || !strings.Contains(out, `"activity": "OffWork"`) {
		t.Errorf("offline should map to Offline/OffWork:\n%s", out)
	}
}

func TestTeamsGraphRevertAfterBecomesExpiration(t *testing.T) {
	out, err := run(t, "teams", "set", "busy", "-n", "--revert-after", "45m")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"expirationDuration": "PT45M"`) {
		t.Errorf("--revert-after should become an ISO 8601 expirationDuration:\n%s", out)
	}
	// Graph enforces the expiry, so nothing should claim it will wait.
	if strings.Contains(out, "would wait") {
		t.Errorf("graph transport should not block for the revert:\n%s", out)
	}
}

func TestTeamsGraphRejectsRevertTo(t *testing.T) {
	// Graph expiry always falls back to calculated presence, so a targeted
	// revert cannot be honoured and must be refused rather than ignored.
	out, err := run(t, "teams", "set", "busy", "-n", "--revert-after", "10m", "--revert-to", "away")
	if err == nil {
		t.Fatalf("--revert-to with --via graph should error:\n%s", out)
	}
	if !strings.Contains(err.Error(), "--revert-to is not supported") {
		t.Errorf("error should name the unsupported flag, got: %v", err)
	}
}

func TestTeamsAppleScriptRevertToStillWorks(t *testing.T) {
	out, err := run(t, "teams", "set", "busy", "-n", "--via", "applescript",
		"--revert-after", "10m", "--revert-to", "away")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "would wait 10m0s then set presence to away") {
		t.Errorf("applescript revert should still block and target a status:\n%s", out)
	}
}

func TestTeamsClearRequiresGraph(t *testing.T) {
	if _, err := run(t, "teams", "clear", "-n", "--via", "applescript"); err == nil {
		t.Error("clear via applescript should error: the command box cannot un-set a status")
	}
}

func TestTeamsUnknownTransport(t *testing.T) {
	if _, err := run(t, "teams", "away", "-n", "--via", "telepathy"); err == nil {
		t.Error("an unknown --via should error")
	}
}

func TestTeamsStatusesListsGraphMapping(t *testing.T) {
	out, err := run(t, "teams", "statuses")
	if err != nil {
		t.Fatal(err)
	}
	// Every status must carry a Graph mapping, or the two transports have drifted.
	for _, want := range []string{"DoNotDisturb", "BeRightBack", "Offline/OffWork"} {
		if !strings.Contains(out, want) {
			t.Errorf("statuses output missing %q:\n%s", want, out)
		}
	}
}

func TestTeamsSetUnknownStatus(t *testing.T) {
	if _, err := run(t, "teams", "set", "lunch", "-n"); err == nil {
		t.Error("unknown status should error")
	}
}

func TestLaunchdInstallDryRunRendersPlist(t *testing.T) {
	out, err := run(t, "launchd", "install", "-n", "--name", "unit-test",
		"--at", "Mon-Fri@09:00", "--", "/bin/echo", "hi")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"com.devtools.unit-test",
		"<key>StartCalendarInterval</key>",
		"<string>/bin/echo</string>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plist missing %q:\n%s", want, out)
		}
	}
}

func TestLaunchdInstallRequiresName(t *testing.T) {
	if _, err := run(t, "launchd", "install", "-n", "--interval", "5m", "--", "/bin/echo"); err == nil {
		t.Error("--name should be required")
	}
}

func TestLaunchdInstallRejectsNoTrigger(t *testing.T) {
	if _, err := run(t, "launchd", "install", "-n", "--name", "x", "--", "/bin/echo"); err == nil {
		t.Error("an agent with no trigger should be rejected")
	}
}

func TestCronAddDryRunRendersLine(t *testing.T) {
	out, err := run(t, "cron", "add", "-n", "--name", "unit-test",
		"--schedule", "30 17 * * 1-5", "--", "/bin/echo", "hi")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "30 17 * * 1-5 /bin/echo hi # devtools:unit-test") {
		t.Errorf("cron line missing:\n%s", out)
	}
}

func TestCronAddRejectsBadSchedule(t *testing.T) {
	if _, err := run(t, "cron", "add", "-n", "--name", "x", "--schedule", "* * *", "--", "/bin/echo"); err == nil {
		t.Error("a 3-field schedule should be rejected")
	}
}

func TestVersion(t *testing.T) {
	out, err := run(t, "version")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) == "" {
		t.Error("version printed nothing")
	}
}

func TestWebCheckJSONAndExitCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer srv.Close()

	out, err := run(t, "web", "check", srv.URL, "--json", "--expect-status", "200")
	if err != nil {
		t.Fatalf("a passing check should not error: %v\n%s", err, out)
	}
	var rep map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &rep); jsonErr != nil {
		t.Fatalf("--json did not produce JSON: %v\n%s", jsonErr, out)
	}
	if rep["command"] != "web check" {
		t.Errorf("command = %v", rep["command"])
	}

	// A failed assertion exits 2 through ExitError rather than cobra's 1.
	out, err = run(t, "web", "check", srv.URL, "--expect-status", "404")
	var exit *ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("want an ExitError, got %v\n%s", err, out)
	}
	if exit.Code != check.ExitFailed {
		t.Errorf("exit code = %d, want %d", exit.Code, check.ExitFailed)
	}
	if !strings.Contains(out, "FAIL  expect status") {
		t.Errorf("the report should still print:\n%s", out)
	}
}

func TestWebCheckStrictTurnsWarningsIntoFailures(t *testing.T) {
	// No security headers at all, so the advisory check warns.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	if _, err := run(t, "web", "check", srv.URL); err != nil {
		t.Errorf("warnings alone should exit 0: %v", err)
	}

	_, err := run(t, "web", "check", srv.URL, "--strict")
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != check.ExitWarnings {
		t.Errorf("--strict should exit %d, got %v", check.ExitWarnings, err)
	}
}

func TestWebCheckRejectsBadExpectations(t *testing.T) {
	for _, args := range [][]string{
		{"web", "check", "example.com", "--expect-status", "banana"},
		{"web", "check", "example.com", "--expect-header", "name~([“"},
		{"web", "check", "example.com", "--expect-body", "~([“"},
		{"web", "check", "example.com", "--min-tls", "9.9"},
		{"web", "check", "example.com", "--resolve-to", "not-an-ip"},
	} {
		if _, err := run(t, args...); err == nil {
			t.Errorf("%v should be rejected", args[3:])
		}
	}
}
