package teams

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakePoster records what the transport would send, so the mapping can be
// checked without a token or a network.
type fakePoster struct {
	path   string
	body   any
	posted bool
	err    error
}

func (f *fakePoster) UserPath(suffix string) (string, error) {
	return "/users/user-xyz/" + suffix, nil
}

func (f *fakePoster) Post(_ context.Context, path string, body any) error {
	f.posted, f.path, f.body = true, path, body
	return f.err
}

// TestEveryStatusHasAGraphMapping guards against the two transports drifting:
// a status added for AppleScript with no availability/activity pair would
// silently fail on the default transport.
func TestEveryStatusHasAGraphMapping(t *testing.T) {
	for _, st := range Statuses {
		if st.Availability == "" || st.Activity == "" {
			t.Errorf("status %q has no Graph mapping (availability=%q activity=%q)",
				st.Name, st.Availability, st.Activity)
		}
	}
}

// TestGraphMappingsAreSupportedCombinations pins the mapping to the
// combinations Graph documents as valid. Anything else is a 400.
func TestGraphMappingsAreSupportedCombinations(t *testing.T) {
	supported := map[string]string{
		"Available":    "Available",
		"Busy":         "Busy",
		"DoNotDisturb": "DoNotDisturb",
		"BeRightBack":  "BeRightBack",
		"Away":         "Away",
		"Offline":      "OffWork", // the one pair that is not a repeat
	}
	for _, st := range Statuses {
		want, ok := supported[st.Availability]
		if !ok {
			t.Errorf("status %q uses availability %q, which Graph does not accept", st.Name, st.Availability)
			continue
		}
		if st.Activity != want {
			t.Errorf("status %q: availability %q must pair with activity %q, got %q",
				st.Name, st.Availability, want, st.Activity)
		}
	}
}

func TestISODuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, ""},
		{-5 * time.Minute, ""},
		{45 * time.Minute, "PT45M"},
		{8 * time.Hour, "PT8H"},
		{90 * time.Minute, "PT1H30M"},
		{time.Hour + 2*time.Minute + 3*time.Second, "PT1H2M3S"},
		{30 * time.Second, "PT30S"},
		// Sub-second precision is not meaningful for presence expiry.
		{1500 * time.Millisecond, "PT2S"},
	}
	for _, tc := range cases {
		if got := ISODuration(tc.in); got != tc.want {
			t.Errorf("ISODuration(%s): want %q, got %q", tc.in, tc.want, got)
		}
	}
}

func TestGraphBodyOmitsExpirationWhenNoHold(t *testing.T) {
	st, err := Resolve("dnd")
	if err != nil {
		t.Fatal(err)
	}
	body := GraphBody(st, 0)
	if body.ExpirationDuration != "" {
		t.Errorf("no hold should leave expiration to Graph's default, got %q", body.ExpirationDuration)
	}
	if body.Availability != "DoNotDisturb" || body.Activity != "DoNotDisturb" {
		t.Errorf("unexpected mapping: %+v", body)
	}
}

func TestSetViaGraphPostsPreferredPresence(t *testing.T) {
	st, err := Resolve("away")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakePoster{}
	if err := SetViaGraph(context.Background(), f, st, 45*time.Minute); err != nil {
		t.Fatal(err)
	}
	if f.path != "/users/user-xyz/presence/setUserPreferredPresence" {
		t.Errorf("unexpected path: %s", f.path)
	}
	body, ok := f.body.(PreferredPresence)
	if !ok {
		t.Fatalf("unexpected body type %T", f.body)
	}
	if body.Availability != "Away" || body.Activity != "Away" {
		t.Errorf("unexpected availability/activity: %+v", body)
	}
	if body.ExpirationDuration != "PT45M" {
		t.Errorf("hold should become an ISO 8601 duration, got %q", body.ExpirationDuration)
	}
}

func TestSetViaGraphRejectsUnmappedStatus(t *testing.T) {
	f := &fakePoster{}
	err := SetViaGraph(context.Background(), f, Status{Name: "lunch"}, 0)
	if err == nil {
		t.Fatal("a status with no Graph mapping should error")
	}
	if f.posted {
		t.Error("nothing should be posted for an unmapped status")
	}
}

func TestClearViaGraphSendsNoBody(t *testing.T) {
	f := &fakePoster{}
	if err := ClearViaGraph(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if f.path != "/users/user-xyz/presence/clearUserPreferredPresence" {
		t.Errorf("unexpected path: %s", f.path)
	}
	if f.body != nil {
		t.Errorf("clear takes no body, got %#v", f.body)
	}
}

func TestSetViaGraphPropagatesPostError(t *testing.T) {
	st, _ := Resolve("busy")
	want := errors.New("boom")
	f := &fakePoster{err: want}
	if err := SetViaGraph(context.Background(), f, st, 0); !errors.Is(err, want) {
		t.Errorf("post error should propagate, got %v", err)
	}
}
