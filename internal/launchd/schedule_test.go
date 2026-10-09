package launchd

import "testing"

func deref(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}

func TestParseAtDaily(t *testing.T) {
	got, err := ParseAt("09:00")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	if deref(got[0].Hour) != 9 || deref(got[0].Minute) != 0 {
		t.Errorf("got %+v", got[0])
	}
	if got[0].Weekday != nil {
		t.Error("a daily schedule should not pin a weekday")
	}
}

func TestParseAtWeekdayRange(t *testing.T) {
	got, err := ParseAt("Mon-Fri@08:45")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("want 5 entries, got %d", len(got))
	}
	for i, e := range got {
		if deref(e.Weekday) != i+1 {
			t.Errorf("entry %d weekday = %d, want %d", i, deref(e.Weekday), i+1)
		}
		if deref(e.Hour) != 8 || deref(e.Minute) != 45 {
			t.Errorf("entry %d time = %+v", i, e)
		}
	}
}

func TestParseAtWrappingRange(t *testing.T) {
	got, err := ParseAt("fri-mon@22:00")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{5, 6, 0, 1} // Fri, Sat, Sun, Mon
	if len(got) != len(want) {
		t.Fatalf("want %d entries, got %d", len(want), len(got))
	}
	for i, wd := range want {
		if deref(got[i].Weekday) != wd {
			t.Errorf("entry %d weekday = %d, want %d", i, deref(got[i].Weekday), wd)
		}
	}
}

func TestParseAtAliasesAndWildcards(t *testing.T) {
	if got, _ := ParseAt("weekdays@17:30"); len(got) != 5 {
		t.Errorf("weekdays should expand to 5 entries, got %d", len(got))
	}
	if got, _ := ParseAt("weekends@11:00"); len(got) != 2 {
		t.Errorf("weekends should expand to 2 entries, got %d", len(got))
	}
	if got, _ := ParseAt("mon,wed,fri@18:30"); len(got) != 3 {
		t.Errorf("explicit list should give 3 entries, got %d", len(got))
	}
	// Mon-Sun covers the week, which means "no weekday key at all".
	got, err := ParseAt("mon-sun@06:00")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Weekday != nil {
		t.Errorf("a full week should collapse to one dayless entry, got %+v", got)
	}

	hourly, err := ParseAt("*@*:15")
	if err != nil {
		t.Fatal(err)
	}
	if len(hourly) != 1 || hourly[0].Hour != nil || deref(hourly[0].Minute) != 15 {
		t.Errorf("hourly-at-15 got %+v", hourly)
	}
}

func TestParseAtErrors(t *testing.T) {
	for _, bad := range []string{"", "9am", "25:00", "09:61", "*:*", "funday@09:00", "mon-funday@09:00", "09"} {
		if _, err := ParseAt(bad); err == nil {
			t.Errorf("ParseAt(%q) should fail", bad)
		}
	}
}

func TestDescribeEntry(t *testing.T) {
	entries, _ := ParseAt("Mon-Fri@08:45")
	if got := DescribeEntry(entries[0]); got != "Mon@08:45" {
		t.Errorf("DescribeEntry = %q", got)
	}
	daily, _ := ParseAt("07:05")
	if got := DescribeEntry(daily[0]); got != "daily@07:05" {
		t.Errorf("DescribeEntry = %q", got)
	}
}
