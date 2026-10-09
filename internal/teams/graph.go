package teams

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Poster is the slice of a Microsoft Graph client this package needs. Taking
// an interface keeps the presence vocabulary free of HTTP, and lets the
// transport be tested without a network or a token.
type Poster interface {
	// UserPath builds a /users/{id}/... path for the signed-in user.
	UserPath(suffix string) (string, error)
	// Post sends a JSON body; a nil body sends no content.
	Post(ctx context.Context, path string, body any) error
}

// PreferredPresence is the setUserPreferredPresence request body.
type PreferredPresence struct {
	Availability string `json:"availability"`
	Activity     string `json:"activity"`
	// ExpirationDuration is an ISO 8601 duration. Omitted, Graph applies its
	// own default: 1 day for Busy and DoNotDisturb, 7 days for everything
	// else - so an unattended "busy" does not stick forever.
	ExpirationDuration string `json:"expirationDuration,omitempty"`
}

// GraphBody builds the request body for a status, holding it for hold before
// Graph lets presence fall back to calculated. A zero hold leaves the
// expiration to Graph's default.
func GraphBody(st Status, hold time.Duration) PreferredPresence {
	return PreferredPresence{
		Availability:       st.Availability,
		Activity:           st.Activity,
		ExpirationDuration: ISODuration(hold),
	}
}

// SetViaGraph sets preferred presence through Microsoft Graph. Unlike the
// AppleScript path this needs no Accessibility permission and does not steal
// focus, but Teams must still be signed in somewhere: Graph only applies a
// preferred presence while the user has a presence session, and reports
// Offline otherwise.
func SetViaGraph(ctx context.Context, p Poster, st Status, hold time.Duration) error {
	if st.Availability == "" {
		return fmt.Errorf("status %q has no Graph availability mapping", st.Name)
	}
	path, err := p.UserPath("presence/setUserPreferredPresence")
	if err != nil {
		return err
	}
	return p.Post(ctx, path, GraphBody(st, hold))
}

// ClearViaGraph removes the preferred presence, handing presence back to
// whatever Teams calculates. This has no AppleScript equivalent - the command
// box can only set a status, never un-set one.
func ClearViaGraph(ctx context.Context, p Poster) error {
	path, err := p.UserPath("presence/clearUserPreferredPresence")
	if err != nil {
		return err
	}
	return p.Post(ctx, path, nil)
}

// ISODuration renders a duration the way Graph's expirationDuration wants it:
// an ISO 8601 duration such as PT45M or PT1H30M. Sub-second precision is
// dropped, since presence expiry is not that fine-grained.
func ISODuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d <= 0 {
		return ""
	}
	h := int64(d / time.Hour)
	m := int64((d % time.Hour) / time.Minute)
	s := int64((d % time.Minute) / time.Second)

	var b strings.Builder
	b.WriteString("PT")
	if h > 0 {
		fmt.Fprintf(&b, "%dH", h)
	}
	if m > 0 {
		fmt.Fprintf(&b, "%dM", m)
	}
	if s > 0 {
		fmt.Fprintf(&b, "%dS", s)
	}
	return b.String()
}
