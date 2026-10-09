package launchd

import (
	"fmt"
	"strconv"
	"strings"
)

// CalendarEntry is one StartCalendarInterval dict. A nil field means "every".
type CalendarEntry struct {
	Minute  *int
	Hour    *int
	Day     *int
	Weekday *int // 0 and 7 are both Sunday to launchd
	Month   *int
}

func intp(v int) *int { return &v }

var weekdays = map[string]int{
	"sun": 0, "sunday": 0,
	"mon": 1, "monday": 1,
	"tue": 2, "tues": 2, "tuesday": 2,
	"wed": 3, "weds": 3, "wednesday": 3,
	"thu": 4, "thur": 4, "thurs": 4, "thursday": 4,
	"fri": 5, "friday": 5,
	"sat": 6, "saturday": 6,
}

var weekdayNames = []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}

// ParseAt turns a human schedule spec into StartCalendarInterval entries.
//
// Accepted forms:
//
//	09:00                 every day at 09:00
//	Mon-Fri@09:00         weekdays at 09:00
//	mon,wed,fri@18:30     those days at 18:30
//	weekdays@08:45        alias for Mon-Fri
//	weekends@11:00        alias for Sat,Sun
//	daily@07:00           alias for every day
//	*@*:15                every hour at :15
func ParseAt(spec string) ([]CalendarEntry, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty schedule")
	}

	days, clock := "", spec
	if i := strings.Index(spec, "@"); i >= 0 {
		days, clock = strings.TrimSpace(spec[:i]), strings.TrimSpace(spec[i+1:])
	}

	hour, minute, err := parseClock(clock)
	if err != nil {
		return nil, fmt.Errorf("schedule %q: %w", spec, err)
	}

	wds, err := parseDays(days)
	if err != nil {
		return nil, fmt.Errorf("schedule %q: %w", spec, err)
	}

	if len(wds) == 0 { // every day
		return []CalendarEntry{{Minute: minute, Hour: hour}}, nil
	}
	out := make([]CalendarEntry, 0, len(wds))
	for _, wd := range wds {
		out = append(out, CalendarEntry{Minute: minute, Hour: hour, Weekday: intp(wd)})
	}
	return out, nil
}

// parseClock handles HH:MM with "*" allowed in either position.
func parseClock(clock string) (hour, minute *int, err error) {
	if clock == "" {
		return nil, nil, fmt.Errorf("missing HH:MM")
	}
	parts := strings.Split(clock, ":")
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("want HH:MM, got %q", clock)
	}
	hour, err = parseField(parts[0], 0, 23)
	if err != nil {
		return nil, nil, fmt.Errorf("hour: %w", err)
	}
	minute, err = parseField(parts[1], 0, 59)
	if err != nil {
		return nil, nil, fmt.Errorf("minute: %w", err)
	}
	if hour == nil && minute == nil {
		return nil, nil, fmt.Errorf("*:* would run every minute; give at least one value")
	}
	return hour, minute, nil
}

func parseField(s string, min, max int) (*int, error) {
	s = strings.TrimSpace(s)
	if s == "*" || s == "" {
		return nil, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return nil, fmt.Errorf("%q is not a number or *", s)
	}
	if n < min || n > max {
		return nil, fmt.Errorf("%d out of range %d-%d", n, min, max)
	}
	return intp(n), nil
}

// parseDays expands a day spec into weekday numbers. An empty result means
// "every day" (no Weekday key at all).
func parseDays(spec string) ([]int, error) {
	spec = strings.ToLower(strings.TrimSpace(spec))
	switch spec {
	case "", "*", "daily", "everyday", "every-day", "all":
		return nil, nil
	case "weekdays", "weekday":
		spec = "mon-fri"
	case "weekends", "weekend":
		spec = "sat,sun"
	}

	seen := map[int]bool{}
	var out []int
	add := func(n int) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}

	for _, chunk := range strings.Split(spec, ",") {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(chunk, "-")
		if !isRange {
			n, ok := weekdays[chunk]
			if !ok {
				return nil, fmt.Errorf("unknown day %q", chunk)
			}
			add(n)
			continue
		}
		start, ok := weekdays[strings.TrimSpace(lo)]
		if !ok {
			return nil, fmt.Errorf("unknown day %q", lo)
		}
		end, ok := weekdays[strings.TrimSpace(hi)]
		if !ok {
			return nil, fmt.Errorf("unknown day %q", hi)
		}
		// Walk forward so Fri-Mon wraps the weekend the way a human means it.
		for d := start; ; d = (d + 1) % 7 {
			add(d)
			if d == end {
				break
			}
		}
	}
	if len(out) == 7 {
		return nil, nil // every day; drop the Weekday key
	}
	return out, nil
}

// DescribeEntry renders a CalendarEntry back as a human-readable spec.
func DescribeEntry(e CalendarEntry) string {
	val := func(p *int, width int) string {
		if p == nil {
			return "*"
		}
		return fmt.Sprintf("%0*d", width, *p)
	}
	day := "daily"
	if e.Weekday != nil {
		day = weekdayNames[*e.Weekday%7]
	}
	return fmt.Sprintf("%s@%s:%s", day, val(e.Hour, 2), val(e.Minute, 2))
}
