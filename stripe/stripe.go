// Package stripe is the Stripe gateway for web subscriptions: Checkout to subscribe, the customer
// portal to manage, webhooks to stay in sync, and renewal turned off and on from the server.
//
// The Stripe webhook endpoint must be created with the API version this SDK pins (sgo.APIVersion);
// events of other versions are rejected rather than misread.
package stripe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// SetCustomerEmail changes where Stripe sends the customer's receipts and invoices, as when the
// account's email changes.
func (g *Gateway) SetCustomerEmail(ctx context.Context, customer, email string) error {
	_, err := g.client.V1Customers.Update(ctx, customer, &sgo.CustomerUpdateParams{Email: sgo.String(email)})
	return gatewayError(err)
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

// subscriptionEvents are about a subscription; everything else is acknowledged and ignored (invoice
// events always come with a matching subscription update).
var subscriptionEvents = map[sgo.EventType]bool{
	"customer.subscription.created":                true,
	"customer.subscription.updated":                true,
	"customer.subscription.deleted":                true,
	"customer.subscription.paused":                 true,
	"customer.subscription.resumed":                true,
	"customer.subscription.pending_update_applied": true,
	"customer.subscription.pending_update_expired": true,
}

// subscriptionID verifies the Stripe-Signature header and returns the id of the subscription the
// event is about; empty for other events.
func (g *Gateway) subscriptionID(payload []byte, signature string) (string, error) {
	event, err := webhook.ConstructEvent(payload, signature, g.cfg.WebhookSecret)
	if err != nil {
		return "", fmt.Errorf("stripe: %w: %w", subscription.ErrInvalidNotification, err)
	}
	if !subscriptionEvents[event.Type] {
		return "", nil
	}
	var sub struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil || sub.ID == "" {
		return "", fmt.Errorf("stripe: %w: subscription event without a subscription", subscription.ErrMalformed)
	}
	return sub.ID, nil
}

// current reads a subscription as Stripe has it now.
func (g *Gateway) current(ctx context.Context, ref string) (subscription.State, error) {
	sub, err := g.client.V1Subscriptions.Retrieve(ctx, ref, nil)
	if err != nil {
		return subscription.State{}, gatewayError(err)
	}
	return g.toState(sub), nil
}

// SetAutoRenew turns renewal off or on again, keeping the period already paid for
// (subscription.Renewer).
func (g *Gateway) SetAutoRenew(ctx context.Context, ref string, on bool) error {
	_, err := g.client.V1Subscriptions.Update(ctx, ref, &sgo.SubscriptionUpdateParams{CancelAtPeriodEnd: sgo.Bool(!on)})
	return gatewayError(err)
}

// DeleteCustomer removes the customer and its payment methods, which ends its subscriptions.
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

// Verify reads a subscription by id (subscription.Gateway).
func (g *Gateway) Verify(ctx context.Context, proof string) (subscription.State, error) {
	return g.current(ctx, proof)
}

// Notification verifies a webhook request by its Stripe-Signature and reads the subscription it is
// about from Stripe (subscription.Gateway).
func (g *Gateway) Notification(ctx context.Context, r *http.Request) (*subscription.State, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("stripe: %w: %w", subscription.ErrMalformed, err)
	}
	ref, err := g.subscriptionID(body, r.Header.Get("Stripe-Signature"))
	if err != nil || ref == "" {
		return nil, err
	}
	state, err := g.current(ctx, ref)
	if err != nil {
		return nil, err
	}
	return &state, nil
}
