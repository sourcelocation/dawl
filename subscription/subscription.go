// Package subscription is the vocabulary every store is translated into: where a subscription was
// bought (Provider), where it stands (Status), its verified state as the store reports it (State),
// and the rule that decides whether it grants access right now (Entitles).
//
// It depends on the standard library only, so apps can use it from their domain layer.
package subscription

import "time"

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
