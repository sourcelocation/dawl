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
