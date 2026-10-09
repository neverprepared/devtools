package check

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// StatusMatcher matches HTTP status codes. It accepts exact codes (200), class
// wildcards (2xx), and comma-separated lists of either (200,204,3xx).
type StatusMatcher struct {
	spec    string
	exact   []int
	classes []int // first digit, e.g. 2 for 2xx
}

// ParseStatusMatcher parses an --expect-status value.
func ParseStatusMatcher(spec string) (StatusMatcher, error) {
	m := StatusMatcher{spec: spec}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		if strings.HasSuffix(part, "xx") && len(part) == 3 {
			d, err := strconv.Atoi(part[:1])
			if err != nil || d < 1 || d > 5 {
				return m, fmt.Errorf("bad status class %q", part)
			}
			m.classes = append(m.classes, d)
			continue
		}
		code, err := strconv.Atoi(part)
		if err != nil || code < 100 || code > 599 {
			return m, fmt.Errorf("bad status code %q (want 200, 2xx, or a list)", part)
		}
		m.exact = append(m.exact, code)
	}
	if len(m.exact) == 0 && len(m.classes) == 0 {
		return m, fmt.Errorf("empty status expectation")
	}
	return m, nil
}

// Match reports whether code satisfies the matcher.
func (m StatusMatcher) Match(code int) bool {
	for _, c := range m.exact {
		if c == code {
			return true
		}
	}
	for _, d := range m.classes {
		if code/100 == d {
			return true
		}
	}
	return false
}

// String returns the original spec.
func (m StatusMatcher) String() string { return m.spec }

// IsZero reports whether no expectation was set.
func (m StatusMatcher) IsZero() bool { return len(m.exact) == 0 && len(m.classes) == 0 }

// HeaderExpectation asserts something about one response header.
//
//	Name              the header must be present
//	Name=value        case-insensitive exact match
//	Name~regex        the value must match the regular expression
//	!Name             the header must be absent
type HeaderExpectation struct {
	spec   string
	Name   string
	Value  string
	Regexp *regexp.Regexp
	Absent bool
}

// ParseHeaderExpectation parses an --expect-header value.
func ParseHeaderExpectation(spec string) (HeaderExpectation, error) {
	h := HeaderExpectation{spec: spec}
	raw := strings.TrimSpace(spec)
	if raw == "" {
		return h, fmt.Errorf("empty header expectation")
	}
	if strings.HasPrefix(raw, "!") {
		h.Absent = true
		h.Name = strings.TrimSpace(raw[1:])
		if h.Name == "" {
			return h, fmt.Errorf("!%s names no header", raw)
		}
		return h, nil
	}
	// Check "~" before "=" so a regex containing = is not split on it.
	if name, pattern, ok := strings.Cut(raw, "~"); ok {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return h, fmt.Errorf("header %s: bad regexp: %w", name, err)
		}
		h.Name, h.Regexp = strings.TrimSpace(name), re
		return h, nil
	}
	if name, value, ok := strings.Cut(raw, "="); ok {
		h.Name, h.Value = strings.TrimSpace(name), strings.TrimSpace(value)
		return h, nil
	}
	h.Name = raw
	return h, nil
}

// Check evaluates the expectation against a response header set.
func (h HeaderExpectation) Check(header http.Header) Result {
	name := "header " + h.Name
	got := header.Values(h.Name)

	switch {
	case h.Absent:
		if len(got) == 0 {
			return OK(name, "absent, as expected")
		}
		return Failf(name, "expected absent, got %q", strings.Join(got, ", "))
	case len(got) == 0:
		return Failf(name, "missing")
	case h.Regexp != nil:
		for _, v := range got {
			if h.Regexp.MatchString(v) {
				return OK(name, "%q matches /%s/", v, h.Regexp)
			}
		}
		return Failf(name, "%q does not match /%s/", strings.Join(got, ", "), h.Regexp)
	case h.Value != "":
		for _, v := range got {
			if strings.EqualFold(strings.TrimSpace(v), h.Value) {
				return OK(name, "%q", v)
			}
		}
		return Failf(name, "want %q, got %q", h.Value, strings.Join(got, ", "))
	default:
		return OK(name, "present (%q)", strings.Join(got, ", "))
	}
}

// String returns the original spec.
func (h HeaderExpectation) String() string { return h.spec }

// BodyExpectation asserts something about the response body.
//
//	text        the body must contain this substring
//	~regex      the body must match this regular expression
//	!text       the body must not contain this substring
type BodyExpectation struct {
	spec   string
	Text   string
	Regexp *regexp.Regexp
	Absent bool
}

// ParseBodyExpectation parses an --expect-body value.
func ParseBodyExpectation(spec string) (BodyExpectation, error) {
	b := BodyExpectation{spec: spec}
	if spec == "" {
		return b, fmt.Errorf("empty body expectation")
	}
	raw := spec
	if strings.HasPrefix(raw, "!") {
		b.Absent, raw = true, raw[1:]
	}
	if strings.HasPrefix(raw, "~") {
		re, err := regexp.Compile(raw[1:])
		if err != nil {
			return b, fmt.Errorf("bad body regexp: %w", err)
		}
		b.Regexp = re
		return b, nil
	}
	b.Text = raw
	return b, nil
}

// Check evaluates the expectation against a response body.
func (b BodyExpectation) Check(body []byte) Result {
	name := "body"
	text := string(body)

	var found bool
	var what string
	if b.Regexp != nil {
		found, what = b.Regexp.MatchString(text), "/"+b.Regexp.String()+"/"
	} else {
		found, what = strings.Contains(text, b.Text), strconv.Quote(b.Text)
	}

	switch {
	case b.Absent && found:
		return Failf(name, "expected not to contain %s, but it does", what)
	case b.Absent:
		return OK(name, "does not contain %s, as expected", what)
	case found:
		return OK(name, "contains %s", what)
	default:
		return Failf(name, "does not contain %s", what)
	}
}

// String returns the original spec.
func (b BodyExpectation) String() string { return b.spec }
