package subscription

import (
	"testing"
	"time"
)

func TestEntitles(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	cases := []struct {
		name   string
		status Status
		end    *time.Time
		want   bool
	}{
		{"active without an end", StatusActive, nil, true},
		{"active in its period", StatusActive, at(time.Hour), true},
		{"active renewal reported late", StatusActive, at(-48 * time.Hour), true},
		{"active long past its period", StatusActive, at(-Grace - time.Second), false},
		{"trialing", StatusTrialing, at(time.Hour), true},
		{"in billing grace", StatusInGrace, at(-time.Hour), true},
		{"canceled before its end", StatusCanceled, at(time.Hour), true},
		{"canceled after its end", StatusCanceled, at(-time.Second), false},
		{"canceled without an end", StatusCanceled, nil, false},
		{"on hold", StatusOnHold, at(time.Hour), false},
		{"paused", StatusPaused, at(time.Hour), false},
		{"expired", StatusExpired, at(time.Hour), false},
		{"revoked", StatusRevoked, at(time.Hour), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Entitles(c.status, c.end, now); got != c.want {
				t.Fatalf("Entitles = %v, want %v", got, c.want)
			}
			if got := (State{Status: c.status, CurrentPeriodEnd: c.end}).Entitles(now); got != c.want {
				t.Fatalf("State.Entitles = %v, want %v", got, c.want)
			}
		})
	}
}
