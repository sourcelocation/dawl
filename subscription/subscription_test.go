package subscription

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestUntil(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	cases := []struct {
		name     string
		state    State
		until    *time.Time // nil: grants nothing
		entitles bool
	}{
		{"active and renewing", State{Status: StatusActive, AutoRenew: true, CurrentPeriodEnd: at(time.Hour)}, at(time.Hour + Grace), true},
		{"renewal reported late", State{Status: StatusActive, AutoRenew: true, CurrentPeriodEnd: at(-48 * time.Hour)}, at(Grace - 48*time.Hour), true},
		{"long past its period", State{Status: StatusActive, AutoRenew: true, CurrentPeriodEnd: at(-Grace - time.Second)}, at(-time.Second), false},
		{"active, renewal off", State{Status: StatusActive, CurrentPeriodEnd: at(time.Hour)}, at(time.Hour), true},
		{"active, renewal off, ended", State{Status: StatusActive, CurrentPeriodEnd: at(-time.Second)}, at(-time.Second), false},
		{"trialing", State{Status: StatusTrialing, AutoRenew: true, CurrentPeriodEnd: at(time.Hour)}, at(time.Hour + Grace), true},
		{"in billing grace", State{Status: StatusInGrace, CurrentPeriodEnd: at(-time.Hour)}, at(Grace - time.Hour), true},
		{"canceled before its end", State{Status: StatusCanceled, CurrentPeriodEnd: at(time.Hour)}, at(time.Hour), true},
		{"canceled after its end", State{Status: StatusCanceled, CurrentPeriodEnd: at(-time.Second)}, at(-time.Second), false},
		{"without an end", State{Status: StatusActive, AutoRenew: true}, nil, false},
		{"with no end yet", State{Status: StatusActive, CurrentPeriodEnd: &Forever}, &Forever, true},
		{"with no end yet, renewing", State{Status: StatusActive, AutoRenew: true, CurrentPeriodEnd: &Forever}, &Forever, true},
		{"on hold", State{Status: StatusOnHold, CurrentPeriodEnd: at(time.Hour)}, nil, false},
		{"paused", State{Status: StatusPaused, CurrentPeriodEnd: at(time.Hour)}, nil, false},
		{"expired", State{Status: StatusExpired, CurrentPeriodEnd: at(time.Hour)}, nil, false},
		{"revoked", State{Status: StatusRevoked, CurrentPeriodEnd: at(time.Hour)}, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			until, ok := c.state.Until()
			if ok != (c.until != nil) || (ok && !until.Equal(*c.until)) {
				t.Fatalf("Until = %v %v, want %v", until, ok, c.until)
			}
			if got := c.state.Entitles(now); got != c.entitles {
				t.Fatalf("Entitles = %v, want %v", got, c.entitles)
			}
		})
	}
}

type fakeGateway struct {
	state *State
	err   error
}

func (f fakeGateway) Verify(context.Context, string) (State, error) { return State{}, nil }

func (f fakeGateway) Notification(context.Context, *http.Request) (*State, error) {
	return f.state, f.err
}

func TestWebhookAnswersSoStoresRetryOnlyWhatMayStillWork(t *testing.T) {
	active := &State{Provider: Stripe, ProviderRef: "sub_1", Status: StatusActive}
	saveFails := errors.New("database down")
	cases := []struct {
		name    string
		gw      fakeGateway
		saveErr error
		status  int
		saved   bool
	}{
		{"saved", fakeGateway{state: active}, nil, http.StatusNoContent, true},
		{"not about a subscription", fakeGateway{}, nil, http.StatusNoContent, false},
		{"forged", fakeGateway{err: fmt.Errorf("x: %w", ErrInvalidNotification)}, nil, http.StatusUnauthorized, false},
		{"malformed", fakeGateway{err: fmt.Errorf("x: %w", ErrMalformed)}, nil, http.StatusBadRequest, false},
		{"store down", fakeGateway{err: fmt.Errorf("x: %w", ErrUnavailable)}, nil, http.StatusInternalServerError, false},
		{"save fails", fakeGateway{state: active}, saveFails, http.StatusInternalServerError, true},
	}
	for _, c := range cases {
		saved := false
		h := Webhook(c.gw, func(_ context.Context, s State) error {
			saved = s.ProviderRef == "sub_1"
			return c.saveErr
		})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")))
		if rec.Code != c.status || saved != c.saved {
			t.Errorf("%s: status %d saved %v, want %d %v", c.name, rec.Code, saved, c.status, c.saved)
		}
	}
}
