package launchd

import (
	"strings"
	"testing"
	"time"
)

func TestQualifyLabel(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"teams-away", LabelPrefix + "teams-away"},
		{LabelPrefix + "teams-away", LabelPrefix + "teams-away"},
		{"com.example.thing", "com.example.thing"},
	} {
		if got := QualifyLabel(tc.in); got != tc.want {
			t.Errorf("QualifyLabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidate(t *testing.T) {
	base := func() *Agent {
		return &Agent{
			Label:         "com.devtools.t",
			Program:       []string{"/bin/echo", "hi"},
			StartInterval: time.Minute,
		}
	}

	if err := base().Validate(); err != nil {
		t.Fatalf("valid agent rejected: %v", err)
	}

	noSchedule := base()
	noSchedule.StartInterval = 0
	if err := noSchedule.Validate(); err == nil {
		t.Error("an agent with no trigger should be rejected")
	}

	both := base()
	both.Calendar = []CalendarEntry{{Hour: intp(9)}}
	if err := both.Validate(); err == nil {
		t.Error("--interval with --at should be rejected")
	}

	noCmd := base()
	noCmd.Program = nil
	if err := noCmd.Validate(); err == nil {
		t.Error("an agent with no command should be rejected")
	}

	tooFast := base()
	tooFast.StartInterval = time.Millisecond
	if err := tooFast.Validate(); err == nil {
		t.Error("a sub-second interval should be rejected")
	}

	missing := base()
	missing.Program = []string{"/nope/does-not-exist"}
	if err := missing.Validate(); err == nil {
		t.Error("a missing program should be rejected")
	}

	// A bare name on PATH is resolved to an absolute path, since launchd
	// execs the program with no PATH lookup of its own.
	bare := base()
	bare.Program = []string{"echo"}
	if err := bare.Validate(); err != nil {
		t.Fatalf("bare program name: %v", err)
	}
	if !strings.HasPrefix(bare.Program[0], "/") {
		t.Errorf("program not resolved to an absolute path: %q", bare.Program[0])
	}
}

func TestPlist(t *testing.T) {
	cal, err := ParseAt("Mon-Fri@08:45")
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{
		Label:            "com.devtools.teams-busy",
		Program:          []string{"/usr/local/bin/devtools", "teams", "busy"},
		WorkingDirectory: "/tmp",
		Env:              map[string]string{"ZED": "1", "ALPHA": "a&b"},
		Calendar:         cal,
		RunAtLoad:        true,
		StdoutPath:       "/tmp/out.log",
	}
	got := a.Plist()

	for _, want := range []string{
		"<key>Label</key>",
		"<string>com.devtools.teams-busy</string>",
		"<string>/usr/local/bin/devtools</string>",
		"<key>StartCalendarInterval</key>",
		"<key>Weekday</key>",
		"<integer>45</integer>",
		"<key>RunAtLoad</key>\n\t<true/>",
		"<string>a&amp;b</string>",
		"<key>ProcessType</key>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("plist missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "<key>StartInterval</key>") {
		t.Error("calendar agent should not carry StartInterval")
	}
	if strings.Contains(got, "<key>KeepAlive</key>") {
		t.Error("KeepAlive should be omitted when false")
	}
	// Env keys are emitted in sorted order for stable diffs.
	if strings.Index(got, "ALPHA") > strings.Index(got, "ZED") {
		t.Error("environment variables should be sorted")
	}
	// Five weekday entries means five dicts in the array.
	if n := strings.Count(got, "<key>Weekday</key>"); n != 5 {
		t.Errorf("want 5 weekday keys, got %d", n)
	}
}

func TestPlistInterval(t *testing.T) {
	a := &Agent{
		Label:         "com.devtools.ping",
		Program:       []string{"/bin/echo"},
		StartInterval: 15 * time.Minute,
		KeepAlive:     true,
	}
	got := a.Plist()
	if !strings.Contains(got, "<key>StartInterval</key>\n\t<integer>900</integer>") {
		t.Errorf("interval not rendered as seconds:\n%s", got)
	}
	if !strings.Contains(got, "<key>KeepAlive</key>\n\t<true/>") {
		t.Errorf("KeepAlive not rendered:\n%s", got)
	}
}
