// Package subscription is the vocabulary every store is translated into: where a subscription was
// bought (Provider), where it stands (Status), its verified state as the store reports it (State),
// the one rule for how long it grants access (State.Until), and what products cost (Price).
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
	Discord    Provider = "discord"
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

// Grace keeps a subscription that may still renew entitled for this long after its period ends, so
// a renewal the store reports late never interrupts access.
const Grace = 72 * time.Hour

// Forever is the period end of access a store grants with no end set yet: a Discord entitlement
// runs until Discord ends it. It fits a database's timestamp, so apps store it like any other end.
var Forever = time.Date(9999, time.December, 31, 0, 0, 0, 0, time.UTC)

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
	// metadata, the App Store's appAccountToken, Play's obfuscatedExternalAccountId or the Discord
	// user who bought it. Empty when the store does not say.
	Account string
	// Covers is what the subscription grants access to when that is something other than Account,
	// as the store reports it: a Discord guild subscription covers its server. Empty when it covers
	// Account. Like Account, dawl never interprets it.
	Covers string
}

// Until is when the subscription stops granting access; ok is false when it grants none. It is the
// end of the period, plus Grace while the store may still renew it (active or trialing with
// renewal on, or in billing grace), and never past Forever. One without a period end grants
// nothing.
//
// Apps that keep "access until" rather than asking at every request store the latest Until of a
// person's subscriptions. Subscriptions an app grants itself fit too: active, renewal off, ending
// when the grant does.
func (s State) Until() (until time.Time, ok bool) {
	if s.CurrentPeriodEnd == nil {
		return time.Time{}, false
	}
	end := *s.CurrentPeriodEnd
	graced := end.Add(Grace)
	if graced.After(Forever) {
		graced = Forever
	}
	switch s.Status {
	case StatusInGrace:
		return graced, true
	case StatusActive, StatusTrialing:
		if s.AutoRenew {
			return graced, true
		}
		return end, true
	case StatusCanceled:
		return end, true
	default:
		return time.Time{}, false
	}
}

// Entitles reports whether the subscription grants access at now.
func (s State) Entitles(now time.Time) bool {
	until, ok := s.Until()
	return ok && now.Before(until)
}

// Gateway is what every store's gateway offers, so an app handles all stores the same way.
type Gateway interface {
	// Verify checks proof of a purchase an app made (an App Store signed transaction, a Play
	// purchase token, a Stripe subscription id) and returns the subscription's verified state.
	// Play purchases are acknowledged on the way.
	Verify(ctx context.Context, proof string) (State, error)
	// Notification verifies a store's notification and returns the subscription it is about, as
	// the store has it now: stores deliver notifications late and out of order, so the gateway
	// reads the subscription again rather than trusting the notification's copy. Saving what it
	// returns is therefore safe in any order and any number of times. Nil for notifications about
	// anything else.
	Notification(ctx context.Context, r *http.Request) (*State, error)
}

// Interval is how often a price is charged.
type Interval string

// The intervals stores charge at.
const (
	Day   Interval = "day"
	Week  Interval = "week"
	Month Interval = "month"
	Year  Interval = "year"
)

// Price is what a product costs, as its store lists it.
type Price struct {
	ProductID string
	Amount    int64  // in the currency's smallest unit (cents)
	Currency  string // ISO 4217, upper case: "USD"
	Interval  Interval
	Every     int // charged every Every intervals: 3 with Month is quarterly
}

// Catalog is a gateway that can say what its products cost, for an app to show before someone
// buys. Stripe's can; the App Store, Play and Discord show their own prices where people buy.
type Catalog interface {
	// Prices reads the prices of products by their store ids, in the same order.
	Prices(ctx context.Context, productIDs ...string) ([]Price, error)
}

// Renewer is a gateway that can turn a subscription's renewal off and on again from the server,
// keeping the period already paid for. Stripe's can; the App Store's and Play's leave that to the
// person, in their store.
type Renewer interface {
	SetAutoRenew(ctx context.Context, ref string, on bool) error
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
		w.Header().Set("Content-Type", "application/json") // Discord wants one even on an empty answer
		w.WriteHeader(http.StatusNoContent)
	})
}
