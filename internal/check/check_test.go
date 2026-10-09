package check

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestStatusMatcher(t *testing.T) {
	for _, tc := range []struct {
		spec  string
		match []int
		miss  []int
	}{
		{"200", []int{200}, []int{201, 404}},
		{"2xx", []int{200, 204, 299}, []int{199, 300}},
		{"200,204,3xx", []int{200, 204, 301, 399}, []int{203, 400}},
		{" 404 ", []int{404}, []int{200}},
	} {
		m, err := ParseStatusMatcher(tc.spec)
		if err != nil {
			t.Fatalf("ParseStatusMatcher(%q): %v", tc.spec, err)
		}
		for _, code := range tc.match {
			if !m.Match(code) {
				t.Errorf("%q should match %d", tc.spec, code)
			}
		}
		for _, code := range tc.miss {
			if m.Match(code) {
				t.Errorf("%q should not match %d", tc.spec, code)
			}
		}
	}

	for _, bad := range []string{"", "abc", "99", "600", "7xx", "2xxx", ","} {
		if _, err := ParseStatusMatcher(bad); err == nil {
			t.Errorf("ParseStatusMatcher(%q) should fail", bad)
		}
	}

	var zero StatusMatcher
	if !zero.IsZero() {
		t.Error("the zero matcher should report IsZero")
	}
}

func TestHeaderExpectation(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Add("Set-Cookie", "a=1")
	h.Add("Set-Cookie", "b=2")

	for _, tc := range []struct {
		spec string
		want Status
	}{
		{"content-type", Pass},            // present
		{"cache-control=no-store", Pass},  // exact, case-insensitive name
		{"Cache-Control=NO-STORE", Pass},  // case-insensitive value
		{"cache-control=no-cache", Fail},  // wrong value
		{"content-type~^text/html", Pass}, // regex
		{"content-type~^application/json", Fail},
		{"set-cookie=b=2", Pass}, // value containing = and multi-valued
		{"!x-powered-by", Pass},  // absent, as expected
		{"!content-type", Fail},  // present but expected absent
		{"x-missing", Fail},      // missing
	} {
		e, err := ParseHeaderExpectation(tc.spec)
		if err != nil {
			t.Fatalf("ParseHeaderExpectation(%q): %v", tc.spec, err)
		}
		if got := e.Check(h); got.Status != tc.want {
			t.Errorf("%q = %s (%s), want %s", tc.spec, got.Status, got.Detail, tc.want)
		}
	}

	for _, bad := range []string{"", "!", "name~([", "   "} {
		if _, err := ParseHeaderExpectation(bad); err == nil {
			t.Errorf("ParseHeaderExpectation(%q) should fail", bad)
		}
	}
}

func TestBodyExpectation(t *testing.T) {
	body := []byte(`{"status":"ok","count":3}`)
	for _, tc := range []struct {
		spec string
		want Status
	}{
		{`"status":"ok"`, Pass},
		{`"status":"down"`, Fail},
		{`~"count":\s*\d+`, Pass},
		{`~^\[`, Fail},
		{`!"status":"down"`, Pass},
		{`!"status":"ok"`, Fail},
		{`!~"count":\s*\d+`, Fail},
	} {
		e, err := ParseBodyExpectation(tc.spec)
		if err != nil {
			t.Fatalf("ParseBodyExpectation(%q): %v", tc.spec, err)
		}
		if got := e.Check(body); got.Status != tc.want {
			t.Errorf("%q = %s (%s), want %s", tc.spec, got.Status, got.Detail, tc.want)
		}
	}
	if _, err := ParseBodyExpectation("~([“"); err == nil {
		t.Error("a bad regexp should fail to parse")
	}
	if _, err := ParseBodyExpectation(""); err == nil {
		t.Error("an empty expectation should fail to parse")
	}
}

func TestReportExitCodes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		steps   []Result
		strict  bool
		summary Status
		exit    int
	}{
		{"all pass", []Result{OK("a", "fine")}, false, Pass, ExitOK},
		{"warn lenient", []Result{OK("a", "fine"), Warnf("b", "hmm")}, false, Warn, ExitOK},
		{"warn strict", []Result{Warnf("b", "hmm")}, true, Warn, ExitWarnings},
		{"fail beats warn", []Result{Warnf("b", "hmm"), Failf("c", "broken")}, false, Fail, ExitFailed},
		{"fail strict", []Result{Failf("c", "broken")}, true, Fail, ExitFailed},
		{"skip only", []Result{Skipf("a", "n/a")}, true, Skip, ExitOK},
	} {
		r := NewReport("test", "target")
		for _, s := range tc.steps {
			r.Add(s)
		}
		if got := r.Finalize(tc.strict); got != tc.exit {
			t.Errorf("%s: exit = %d, want %d", tc.name, got, tc.exit)
		}
		if r.Summary != tc.summary {
			t.Errorf("%s: summary = %s, want %s", tc.name, r.Summary, tc.summary)
		}
	}
}

func TestResultNoteAndElapsed(t *testing.T) {
	r := OK("step", "detail %d", 1).Note("extra %s", "line").Elapsed(1500 * time.Microsecond)
	if r.Detail != "detail 1" {
		t.Errorf("Detail = %q", r.Detail)
	}
	if len(r.Notes) != 1 || r.Notes[0] != "extra line" {
		t.Errorf("Notes = %v", r.Notes)
	}
	if r.ElapsedMS != 1.5 {
		t.Errorf("ElapsedMS = %v, want 1.5", r.ElapsedMS)
	}
}

func TestRenderText(t *testing.T) {
	r := NewReport("web check", "https://example.com/")
	r.Add(OK("dns", "example.com -> 1.2.3.4").Elapsed(12 * time.Millisecond))
	r.Add(Failf("tls", "certificate expired").Note("expires 2020-01-01"))
	r.Timing = &Timing{DNSMS: 12, TTFBMS: 150, TotalMS: 160}
	r.Finalize(false)

	var buf bytes.Buffer
	r.RenderText(&buf)
	out := buf.String()

	for _, want := range []string{
		"WEB CHECK  https://example.com/",
		"ok    dns",
		"FAIL  tls  certificate expired",
		"expires 2020-01-01",
		"timing  dns 12ms   ttfb 150ms   total 160ms",
		"FAIL: 1 pass, 1 fail",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderJSON(t *testing.T) {
	r := NewReport("web check", "https://example.com/")
	r.Add(OK("dns", "resolved"))
	r.Set("dns", map[string]string{"host": "example.com"})
	r.Finalize(false)

	var buf bytes.Buffer
	if err := r.RenderJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if back["summary"] != "pass" {
		t.Errorf("summary = %v", back["summary"])
	}
	if back["exit_code"].(float64) != 0 {
		t.Errorf("exit_code = %v", back["exit_code"])
	}
	data := back["data"].(map[string]any)["dns"].(map[string]any)
	if data["host"] != "example.com" {
		t.Errorf("data.dns.host = %v", data["host"])
	}
}

func TestFormatMS(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want string
	}{
		{1.5, "1.5ms"},
		{150, "150ms"},
		{1500, "1.50s"},
		{12000, "12.0s"},
	} {
		if got := formatMS(tc.in); got != tc.want {
			t.Errorf("formatMS(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
