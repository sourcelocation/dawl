// Package subscription is the vocabulary every store is translated into: where a subscription was
// bought (Provider), where it stands (Status), its verified state as the store reports it (State),
// and the rule that decides whether it grants access right now (Entitles).
//
// It depends on the standard library only.
package subscription

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Provider is where a subscription was purchased. Apps may declare providers of their own.
type Provider string

// Providers with a gateway in this module.
const (
	Stripe     Provider = "stripe"
	AppStore   Provider = "app_store"
	GooglePlay Provider = "google_play"
)

// Status normalises the lifecycle states of every store into one vocabulary.
type Status string

// The statuses a subscription moves through, whichever store sold it.
const (
	StatusActive   Status = "active"
	StatusTrialing Status = "trialing"
	// StatusInGrace means renewal failed, the store is retrying and access continues (billing grace).
	StatusInGrace Status = "in_grace"
	// StatusOnHold means renewal failed and the store suspended access while retrying.
	StatusOnHold   Status = "on_hold"
	StatusPaused   Status = "paused"
	StatusCanceled Status = "canceled" // will not renew; entitled until the period ends
	StatusExpired  Status = "expired"
	StatusRevoked  Status = "revoked" // refunded or revoked by the store
)

// Grace keeps a subscription in good standing entitled for this long after its period ends, so a
// renewal the store reports late never interrupts access.
const Grace = 72 * time.Hour

// Entitles reports whether a subscription with this status and period end grants access at now.
func Entitles(status Status, periodEnd *time.Time, now time.Time) bool {
	switch status {
	case StatusActive, StatusTrialing, StatusInGrace:
		return periodEnd == nil || now.Before(periodEnd.Add(Grace))
	case StatusCanceled:
		return periodEnd != nil && now.Before(*periodEnd)
	default:
		return false
	}
}

// State is a subscription as a store reports it, already verified and normalised.
type State struct {
	Provider         Provider
	ProviderRef      string // Stripe subscription id, App Store original transaction id, Play purchase token
	ProductID        string
	Status           Status
	CurrentPeriodEnd *time.Time
	AutoRenew        bool
	Environment      string // production | sandbox
	// Account is the app's account the purchase was made for, as the store reports it: Stripe
	// metadata, the App Store's appAccountToken or Play's obfuscatedExternalAccountId. Empty when
	// the store does not say.
	Account string
}

// Entitles reports whether the subscription grants access at now.
func (s State) Entitles(now time.Time) bool { return Entitles(s.Status, s.CurrentPeriodEnd, now) }

// Gateway is what every store's gateway offers, so an app handles all stores the same way.
type Gateway interface {
	// Verify checks proof of a purchase an app made (an App Store signed transaction, a Play
	// purchase token, a Stripe subscription id) and returns the subscription's verified state.
	// Play purchases are acknowledged on the way.
	Verify(ctx context.Context, proof string) (State, error)
	// Notification verifies a store's notification and returns the subscription it is about,
	// re-fetched where the store only sends a reference; nil for notifications about anything else.
	Notification(ctx context.Context, r *http.Request) (*State, error)
}

// Webhook serves a store's notifications: each verified subscription goes to save. Requests that
// can't be verified get 401, malformed ones 400, and failures of the store or of save 500, so the
// store delivers again.
func Webhook(gw Gateway, save func(context.Context, State) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, err := gw.Notification(r.Context(), r)
		switch {
		case errors.Is(err, ErrInvalidNotification), errors.Is(err, ErrUnverified):
			http.Error(w, "unverified", http.StatusUnauthorized)
			return
		case errors.Is(err, ErrMalformed):
			http.Error(w, "malformed", http.StatusBadRequest)
			return
		case err != nil:
			http.Error(w, "try again", http.StatusInternalServerError)
			return
		}
		if state != nil {
			if err := save(r.Context(), *state); err != nil {
				http.Error(w, "try again", http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
