// Package stripe is the Stripe gateway for web subscriptions: Checkout to subscribe, the customer
// portal to manage, webhooks to stay in sync.
//
// The Stripe webhook endpoint must be created with the API version this SDK pins (sgo.APIVersion);
// events of other versions are rejected rather than misread.
package stripe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	sgo "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"

	"github.com/sourcelocation/dawl/subscription"
)

// Config holds the Stripe account settings.
type Config struct {
	SecretKey     string
	WebhookSecret string
	// AccountMetadataKey links Stripe customers and subscriptions to the app's accounts
	// (default "account").
	AccountMetadataKey string
	// IdempotencyPrefix namespaces the idempotency keys this gateway sends (e.g. "rondo-").
	IdempotencyPrefix string
	AutomaticTax      bool   // let Stripe Tax compute VAT/sales tax in Checkout
	SuccessURL        string // where Checkout returns after paying
	CancelURL         string // where Checkout returns when abandoned
	PortalReturnURL   string // where the customer portal returns
	APIBase           string // overrides api.stripe.com (stripe-mock in tests)
}

// Gateway talks to Stripe.
type Gateway struct {
	cfg    Config
	client *sgo.Client
}

// New builds the gateway.
func New(cfg Config) *Gateway {
	if cfg.AccountMetadataKey == "" {
		cfg.AccountMetadataKey = "account"
	}
	retries := int64(2)
	backend := &sgo.BackendConfig{HTTPClient: &http.Client{Timeout: 30 * time.Second}, MaxNetworkRetries: &retries}
	if cfg.APIBase != "" {
		backend.URL = &cfg.APIBase
	}
	return &Gateway{cfg: cfg, client: sgo.NewClient(cfg.SecretKey, sgo.WithBackends(sgo.NewBackendsWithConfig(backend)))}
}

// Webhook is a verified Stripe event.
type Webhook struct {
	EventID string
	// Subscription is the subscription's full state for subscription events, nil for every other
	// event (they are acknowledged and ignored).
	Subscription *subscription.State
	Customer     string
}

// EnsureCustomer returns a live customer for the account, creating one when needed. email may be
// empty: Checkout then asks for it.
func (g *Gateway) EnsureCustomer(ctx context.Context, account, email, existing string) (string, error) {
	if existing != "" {
		c, err := g.client.V1Customers.Retrieve(ctx, existing, nil)
		if err == nil && !c.Deleted {
			return existing, nil
		}
		if err != nil && !isMissing(err) {
			return "", gatewayError(err)
		}
	}
	params := &sgo.CustomerCreateParams{Metadata: map[string]string{g.cfg.AccountMetadataKey: account}}
	if email != "" {
		params.Email = sgo.String(email)
	}
	params.SetIdempotencyKey(g.cfg.IdempotencyPrefix + "customer-" + account)
	c, err := g.client.V1Customers.Create(ctx, params)
	if err != nil {
		return "", gatewayError(err)
	}
	return c.ID, nil
}

// CheckoutURL starts a hosted Checkout session subscribing the customer to a price.
func (g *Gateway) CheckoutURL(ctx context.Context, customer, account, price string) (string, error) {
	params := &sgo.CheckoutSessionCreateParams{
		Mode:                sgo.String("subscription"),
		Customer:            sgo.String(customer),
		ClientReferenceID:   sgo.String(account),
		LineItems:           []*sgo.CheckoutSessionCreateLineItemParams{{Price: sgo.String(price), Quantity: sgo.Int64(1)}},
		SubscriptionData:    &sgo.CheckoutSessionCreateSubscriptionDataParams{Metadata: map[string]string{g.cfg.AccountMetadataKey: account}},
		AllowPromotionCodes: sgo.Bool(true),
		SuccessURL:          sgo.String(g.cfg.SuccessURL),
		CancelURL:           sgo.String(g.cfg.CancelURL),
	}
	if g.cfg.AutomaticTax {
		params.AutomaticTax = &sgo.CheckoutSessionCreateAutomaticTaxParams{Enabled: sgo.Bool(true)}
		params.CustomerUpdate = &sgo.CheckoutSessionCreateCustomerUpdateParams{Address: sgo.String("auto"), Name: sgo.String("auto")}
	}
	s, err := g.client.V1CheckoutSessions.Create(ctx, params)
	if err != nil {
		return "", gatewayError(err)
	}
	return s.URL, nil
}

// PortalURL opens the customer portal (payment method, invoices, cancel).
func (g *Gateway) PortalURL(ctx context.Context, customer string) (string, error) {
	s, err := g.client.V1BillingPortalSessions.Create(ctx, &sgo.BillingPortalSessionCreateParams{
		Customer: sgo.String(customer), ReturnURL: sgo.String(g.cfg.PortalReturnURL),
	})
	if err != nil {
		return "", gatewayError(err)
	}
	return s.URL, nil
}

// subscriptionEvents carry the subscription's full state; everything else is acknowledged and
// ignored (invoice events always come with a matching subscription update).
var subscriptionEvents = map[sgo.EventType]bool{
	"customer.subscription.created":                true,
	"customer.subscription.updated":                true,
	"customer.subscription.deleted":                true,
	"customer.subscription.paused":                 true,
	"customer.subscription.resumed":                true,
	"customer.subscription.pending_update_applied": true,
	"customer.subscription.pending_update_expired": true,
}

// ParseWebhook verifies the Stripe-Signature header and decodes subscription events.
func (g *Gateway) ParseWebhook(payload []byte, signature string) (Webhook, error) {
	event, err := webhook.ConstructEvent(payload, signature, g.cfg.WebhookSecret)
	if err != nil {
		return Webhook{}, fmt.Errorf("stripe: %w: %w", subscription.ErrInvalidNotification, err)
	}
	if !subscriptionEvents[event.Type] {
		return Webhook{EventID: event.ID}, nil
	}
	var sub sgo.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
		return Webhook{}, fmt.Errorf("stripe: %w: %w", subscription.ErrMalformed, err)
	}
	customer := ""
	if sub.Customer != nil {
		customer = sub.Customer.ID
	}
	state := g.toState(&sub)
	return Webhook{EventID: event.ID, Subscription: &state, Customer: customer}, nil
}

// Subscription fetches the current state of a subscription.
func (g *Gateway) Subscription(ctx context.Context, ref string) (subscription.State, error) {
	sub, err := g.client.V1Subscriptions.Retrieve(ctx, ref, nil)
	if err != nil {
		return subscription.State{}, gatewayError(err)
	}
	return g.toState(sub), nil
}

// SetCancelAtPeriodEnd stops (or resumes) renewal while keeping the paid period.
func (g *Gateway) SetCancelAtPeriodEnd(ctx context.Context, ref string, cancel bool) error {
	_, err := g.client.V1Subscriptions.Update(ctx, ref, &sgo.SubscriptionUpdateParams{CancelAtPeriodEnd: sgo.Bool(cancel)})
	return gatewayError(err)
}

// CancelSubscription ends a subscription immediately without a final invoice. Cancelling one that
// is already over succeeds.
func (g *Gateway) CancelSubscription(ctx context.Context, ref string) error {
	_, err := g.client.V1Subscriptions.Cancel(ctx, ref, &sgo.SubscriptionCancelParams{InvoiceNow: sgo.Bool(false), Prorate: sgo.Bool(false)})
	if err == nil || isMissing(err) {
		return nil
	}
	if sub, getErr := g.client.V1Subscriptions.Retrieve(ctx, ref, nil); getErr == nil &&
		(sub.Status == sgo.SubscriptionStatusCanceled || sub.Status == sgo.SubscriptionStatusIncompleteExpired) {
		return nil
	}
	return gatewayError(err)
}

// DeleteCustomer removes the customer and its payment methods.
func (g *Gateway) DeleteCustomer(ctx context.Context, customer string) error {
	_, err := g.client.V1Customers.Delete(ctx, customer, nil)
	if isMissing(err) {
		return nil
	}
	return gatewayError(err)
}

// toState normalises a Stripe subscription.
func (g *Gateway) toState(s *sgo.Subscription) subscription.State {
	out := subscription.State{Provider: subscription.Stripe, ProviderRef: s.ID, Environment: "sandbox", Account: s.Metadata[g.cfg.AccountMetadataKey]}
	if s.Livemode {
		out.Environment = "production"
	}
	var periodEnd int64
	if s.Items != nil {
		for _, item := range s.Items.Data {
			periodEnd = max(periodEnd, item.CurrentPeriodEnd)
			if out.ProductID == "" && item.Price != nil {
				out.ProductID = item.Price.ID
			}
		}
	}
	if s.CancelAt != 0 && (periodEnd == 0 || s.CancelAt < periodEnd) {
		periodEnd = s.CancelAt
	}
	if periodEnd != 0 {
		end := time.Unix(periodEnd, 0).UTC()
		out.CurrentPeriodEnd = &end
	}
	ending := s.CancelAtPeriodEnd || s.CancelAt != 0
	switch s.Status {
	case sgo.SubscriptionStatusActive, sgo.SubscriptionStatusTrialing:
		out.Status, out.AutoRenew = subscription.StatusActive, !ending
		if s.Status == sgo.SubscriptionStatusTrialing {
			out.Status = subscription.StatusTrialing
		}
		if ending {
			out.Status = subscription.StatusCanceled // entitled until the period ends
		}
	case sgo.SubscriptionStatusPastDue:
		out.Status, out.AutoRenew = subscription.StatusInGrace, !ending // Stripe is retrying the card
	case sgo.SubscriptionStatusUnpaid, sgo.SubscriptionStatusIncomplete:
		out.Status = subscription.StatusOnHold
	case sgo.SubscriptionStatusPaused:
		out.Status = subscription.StatusPaused
	default: // canceled, incomplete_expired
		out.Status = subscription.StatusExpired
	}
	return out
}

func isMissing(err error) bool {
	var se *sgo.Error
	return errors.As(err, &se) && (se.Code == sgo.ErrorCodeResourceMissing || se.HTTPStatusCode == http.StatusNotFound)
}

// gatewayError wraps Stripe failures: missing objects become ErrNotFound, outages and rate limits
// ErrUnavailable.
func gatewayError(err error) error {
	if err == nil {
		return nil
	}
	var se *sgo.Error
	if errors.As(err, &se) {
		switch {
		case se.HTTPStatusCode == http.StatusNotFound || se.Code == sgo.ErrorCodeResourceMissing:
			return fmt.Errorf("stripe: %w: %w", subscription.ErrNotFound, err)
		case se.HTTPStatusCode >= 500 || se.HTTPStatusCode == http.StatusTooManyRequests:
			return fmt.Errorf("stripe: %w: %w", subscription.ErrUnavailable, err)
		}
		return fmt.Errorf("stripe: %w", err)
	}
	return fmt.Errorf("stripe: %w: %w", subscription.ErrUnavailable, err)
}
