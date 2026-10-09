package crontab

import (
	"strings"
	"testing"
)

const sample = `# hand written, leave alone
0 9 * * * /usr/bin/say hello
*/5 * * * * /usr/local/bin/devtools teams away # devtools:teams-away
@hourly /bin/echo tick # devtools:tick
`

func TestParse(t *testing.T) {
	got := Parse(sample)
	if len(got) != 2 {
		t.Fatalf("want 2 managed entries, got %d: %+v", len(got), got)
	}
	// Sorted by name: teams-away, tick.
	if got[0].Name != "teams-away" || got[1].Name != "tick" {
		t.Fatalf("unexpected names: %q %q", got[0].Name, got[1].Name)
	}
	if got[0].Schedule != "*/5 * * * *" {
		t.Errorf("schedule = %q", got[0].Schedule)
	}
	if got[0].Command != "/usr/local/bin/devtools teams away" {
		t.Errorf("command = %q", got[0].Command)
	}
	if got[1].Schedule != "@hourly" || got[1].Command != "/bin/echo tick" {
		t.Errorf("macro entry parsed wrong: %+v", got[1])
	}
}

func TestUpsertReplacesInPlace(t *testing.T) {
	got := Upsert(sample, "teams-away", "0 17 * * 1-5", "/usr/local/bin/devtools teams away")

	if n := strings.Count(got, "devtools:teams-away"); n != 1 {
		t.Fatalf("want exactly 1 teams-away line, got %d:\n%s", n, got)
	}
	if !strings.Contains(got, "0 17 * * 1-5 /usr/local/bin/devtools teams away # devtools:teams-away") {
		t.Errorf("replacement line missing:\n%s", got)
	}
	if !strings.Contains(got, "# hand written, leave alone") {
		t.Error("hand-written comment was dropped")
	}
	if !strings.Contains(got, "0 9 * * * /usr/bin/say hello") {
		t.Error("unmanaged entry was dropped")
	}
	if !strings.Contains(got, "devtools:tick") {
		t.Error("other managed entry was dropped")
	}
	// Order is preserved: the replacement sits where the original was.
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if !strings.Contains(lines[2], "teams-away") {
		t.Errorf("replacement moved; line 3 is %q", lines[2])
	}
}

func TestUpsertAppends(t *testing.T) {
	got := Upsert(sample, "new-one", "@daily", "/bin/true")
	if !strings.HasSuffix(got, "@daily /bin/true # devtools:new-one\n") {
		t.Errorf("new entry not appended:\n%s", got)
	}
	if len(Parse(got)) != 3 {
		t.Error("want 3 managed entries after append")
	}
}

func TestUpsertOnEmptyCrontab(t *testing.T) {
	got := Upsert("", "only", "@reboot", "/bin/true")
	if got != "@reboot /bin/true # devtools:only\n" {
		t.Errorf("got %q", got)
	}
}

func TestRemove(t *testing.T) {
	got, found := Remove(sample, "tick")
	if !found {
		t.Fatal("tick should have been found")
	}
	if strings.Contains(got, "devtools:tick") {
		t.Errorf("tick not removed:\n%s", got)
	}
	if !strings.Contains(got, "devtools:teams-away") {
		t.Error("removing tick should not touch teams-away")
	}
	if _, found := Remove(sample, "nope"); found {
		t.Error("missing name should report not found")
	}
}

func TestRemoveLastEntryLeavesNoStrayNewline(t *testing.T) {
	got, _ := Remove("@daily /bin/true # devtools:only\n", "only")
	if got != "" {
		t.Errorf("want empty crontab, got %q", got)
	}
}

func TestValidateSchedule(t *testing.T) {
	for _, ok := range []string{"*/5 * * * *", "0 17 * * 1-5", "@hourly", "@reboot", "30 9 1 JAN MON"} {
		if err := ValidateSchedule(ok); err != nil {
			t.Errorf("ValidateSchedule(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "* * * *", "* * * * * *", "@sometimes", "*/5 * * * ;rm"} {
		if err := ValidateSchedule(bad); err == nil {
			t.Errorf("ValidateSchedule(%q) should fail", bad)
		}
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"teams-away", "a.b_c", "x1"} {
		if err := ValidateName(ok); err != nil {
			t.Errorf("ValidateName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "has space", "semi;colon", "hash#tag"} {
		if err := ValidateName(bad); err == nil {
			t.Errorf("ValidateName(%q) should fail", bad)
		}
	}
}
