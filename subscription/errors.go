package subscription

import "errors"

// The gateways wrap the provider's own error in one of these. Apps map them onto their own error
// vocabulary with errors.Is.
var (
	// ErrUnverified: a purchase or transaction failed verification (forged, for another app, or
	// unknown to the store).
	ErrUnverified = errors.New("purchase could not be verified")
	// ErrNotSubscription: a verified purchase that is not a subscription.
	ErrNotSubscription = errors.New("purchase is not a subscription")
	// ErrInvalidNotification: a webhook or store notification that is not authentic, or not meant
	// for this app.
	ErrInvalidNotification = errors.New("notification is not authentic")
	// ErrMalformed: an authentic notification whose payload cannot be read.
	ErrMalformed = errors.New("notification is malformed")
	// ErrNotFound: the store does not know the subscription or customer.
	ErrNotFound = errors.New("not found at the store")
	// ErrUnavailable: the store is down or rate limiting; the call can be retried later.
	ErrUnavailable = errors.New("store is unavailable")
)
