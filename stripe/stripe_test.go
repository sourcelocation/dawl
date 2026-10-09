package stripe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	sgo "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"

	"github.com/sourcelocation/dawl/subscription"
)

const (
	secret  = "whsec_test"
	account = "0199a2b4-0000-7000-8000-0000000000aa"
)

func gateway() *Gateway {
	return New(Config{SecretKey: "sk_test_x", WebhookSecret: secret, AccountMetadataKey: "app_account"})
}

func event(t *testing.T, typ string, object map[string]any) ([]byte, string) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"id": "evt_1", "object": "event", "type": typ, "api_version": sgo.APIVersion, "created": time.Now().Unix(),
		"livemode": false, "data": map[string]any{"object": object},
	})
	if err != nil {
		t.Fatal(err)
	}
	signed := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: payload, Secret: secret})
	return payload, signed.Header
}

func stripeSubscription(status string, cancelAtPeriodEnd bool, periodEnd int64) map[string]any {
	return map[string]any{
		"id": "sub_1", "object": "subscription", "status": status, "customer": "cus_1", "livemode": true,
		"cancel_at_period_end": cancelAtPeriodEnd, "metadata": map[string]string{"app_account": account},
		"items": map[string]any{"object": "list", "data": []map[string]any{{
			"id": "si_1", "object": "subscription_item", "current_period_end": periodEnd,
			"price": map[string]any{"id": "price_yearly", "object": "price"},
		}}},
	}
}

// decode reads a subscription as Stripe's API returns it.
func decode(t *testing.T, object map[string]any) *sgo.Subscription {
	t.Helper()
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	var sub sgo.Subscription
	if err := json.Unmarshal(raw, &sub); err != nil {
		t.Fatal(err)
	}
	return &sub
}

func TestStatesAreNormalised(t *testing.T) {
	end := time.Date(2027, 10, 2, 0, 0, 0, 0, time.UTC).Unix()
	cases := []struct {
		status    string
		ending    bool
		want      subscription.Status
		autoRenew bool
	}{
		{"active", false, subscription.StatusActive, true},
		{"active", true, subscription.StatusCanceled, false},
		{"trialing", false, subscription.StatusTrialing, true},
		{"past_due", false, subscription.StatusInGrace, true},
		{"unpaid", false, subscription.StatusOnHold, false},
		{"incomplete", false, subscription.StatusOnHold, false},
		{"paused", false, subscription.StatusPaused, false},
		{"canceled", false, subscription.StatusExpired, false},
		{"incomplete_expired", false, subscription.StatusExpired, false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s/ending=%v", c.status, c.ending), func(t *testing.T) {
			sub := gateway().toState(decode(t, stripeSubscription(c.status, c.ending, end)))
			if sub.Provider != subscription.Stripe || sub.Status != c.want || sub.AutoRenew != c.autoRenew || sub.ProviderRef != "sub_1" || sub.ProductID != "price_yearly" {
				t.Fatalf("sub = %+v", sub)
			}
			if sub.CurrentPeriodEnd == nil || sub.CurrentPeriodEnd.Unix() != end || sub.Environment != "production" {
				t.Fatalf("period/env = %v %s", sub.CurrentPeriodEnd, sub.Environment)
			}
			if sub.Account != account {
				t.Fatalf("account = %q", sub.Account)
			}
		})
	}
}

// fakeStripe answers for subscription sub_1 and customer cus_1, and remembers what it was asked to
// change.
type fakeStripe struct {
	status string // what Stripe has now
	reads  int
	form   url.Values
}

func newFake(t *testing.T) (*Gateway, *fakeStripe) {
	t.Helper()
	f := &fakeStripe{status: "active"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch {
		case r.URL.Path == "/v1/subscriptions/sub_1" && r.Method == http.MethodGet:
			f.reads++
			_ = json.NewEncoder(w).Encode(stripeSubscription(f.status, false, time.Now().Add(time.Hour).Unix()))
		case r.URL.Path == "/v1/subscriptions/sub_1" && r.Method == http.MethodPost:
			f.form = r.PostForm
			_ = json.NewEncoder(w).Encode(stripeSubscription(f.status, r.PostForm.Get("cancel_at_period_end") == "true", 1))
		case r.URL.Path == "/v1/prices/price_yearly" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "price_yearly", "object": "price", "unit_amount": 12000, "currency": "usd",
				"recurring": map[string]any{"interval": "year", "interval_count": 1}})
		case r.URL.Path == "/v1/customers/cus_1" && r.Method == http.MethodPost:
			f.form = r.PostForm
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "cus_1", "object": "customer"})
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"type": "invalid_request_error", "code": "resource_missing"}})
		}
	}))
	t.Cleanup(srv.Close)
	return New(Config{SecretKey: "sk_test_x", WebhookSecret: secret, AccountMetadataKey: "app_account", APIBase: srv.URL}), f
}

func notification(t *testing.T, payload []byte, signature string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/webhooks/stripe", bytes.NewReader(payload))
	r.Header.Set("Stripe-Signature", signature)
	return r
}

func TestNotificationsReadTheSubscriptionAgain(t *testing.T) {
	gw, store := newFake(t)
	ctx := context.Background()
	// An update that arrives after the subscription was canceled: Stripe's answer wins.
	store.status = "canceled"
	payload, header := event(t, "customer.subscription.updated", stripeSubscription("active", false, time.Now().Add(time.Hour).Unix()))
	sub, err := gw.Notification(ctx, notification(t, payload, header))
	if err != nil || sub == nil || sub.Status != subscription.StatusExpired || store.reads != 1 {
		t.Fatalf("sub=%+v err=%v reads=%d", sub, err, store.reads)
	}

	payload, header = event(t, "invoice.paid", map[string]any{"id": "in_1", "object": "invoice"})
	if sub, err := gw.Notification(ctx, notification(t, payload, header)); err != nil || sub != nil || store.reads != 1 {
		t.Fatalf("other events are acknowledged without reading anything: %+v %v", sub, err)
	}

	forged := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: payload, Secret: "whsec_attacker"})
	if _, err := gw.Notification(ctx, notification(t, payload, forged.Header)); !errors.Is(err, subscription.ErrInvalidNotification) {
		t.Fatalf("forged: %v", err)
	}

	payload, header = event(t, "customer.subscription.deleted", map[string]any{"id": "sub_gone", "object": "subscription"})
	if _, err := gw.Notification(ctx, notification(t, payload, header)); !errors.Is(err, subscription.ErrNotFound) {
		t.Fatalf("a subscription Stripe doesn't know: %v", err)
	}
}

func TestRenewalAndEmailChanges(t *testing.T) {
	gw, store := newFake(t)
	ctx := context.Background()
	var _ subscription.Renewer = gw
	if err := gw.SetAutoRenew(ctx, "sub_1", false); err != nil || store.form.Get("cancel_at_period_end") != "true" {
		t.Fatalf("off: %v %v", err, store.form)
	}
	if err := gw.SetAutoRenew(ctx, "sub_1", true); err != nil || store.form.Get("cancel_at_period_end") != "false" {
		t.Fatalf("on: %v %v", err, store.form)
	}
	if err := gw.SetCustomerEmail(ctx, "cus_1", "new@example.com"); err != nil || store.form.Get("email") != "new@example.com" {
		t.Fatalf("email: %v %v", err, store.form)
	}
	if err := gw.SetAutoRenew(ctx, "sub_gone", false); !errors.Is(err, subscription.ErrNotFound) {
		t.Fatalf("unknown subscription: %v", err)
	}
}

func TestScheduledCancellationEndsAtCancelAt(t *testing.T) {
	s := &sgo.Subscription{
		ID: "sub_1", Status: sgo.SubscriptionStatusActive, CancelAt: 1_800_000_000,
		Items: &sgo.SubscriptionItemList{Data: []*sgo.SubscriptionItem{{CurrentPeriodEnd: 1_900_000_000}}},
	}
	got := gateway().toState(s)
	if got.Status != subscription.StatusCanceled || got.AutoRenew || got.CurrentPeriodEnd.Unix() != 1_800_000_000 {
		t.Fatalf("got %+v", got)
	}
}

func TestGatewayErrors(t *testing.T) {
	cases := []struct {
		err  error
		want error
	}{
		{&sgo.Error{HTTPStatusCode: 404, Code: sgo.ErrorCodeResourceMissing}, subscription.ErrNotFound},
		{&sgo.Error{HTTPStatusCode: 503}, subscription.ErrUnavailable},
		{&sgo.Error{HTTPStatusCode: 429}, subscription.ErrUnavailable},
		{errors.New("connection reset"), subscription.ErrUnavailable},
	}
	for _, c := range cases {
		if got := gatewayError(c.err); !errors.Is(got, c.want) {
			t.Errorf("gatewayError(%v) = %v, want %v", c.err, got, c.want)
		}
	}
	if got := gatewayError(&sgo.Error{HTTPStatusCode: 400}); errors.Is(got, subscription.ErrUnavailable) || errors.Is(got, subscription.ErrNotFound) {
		t.Errorf("a rejected request is neither missing nor an outage: %v", got)
	}
}

func TestPrices(t *testing.T) {
	gw, _ := newFake(t)
	prices, err := gw.Prices(context.Background(), "price_yearly")
	if err != nil {
		t.Fatal(err)
	}
	want := subscription.Price{ProductID: "price_yearly", Amount: 12000, Currency: "USD", Interval: subscription.Year, Every: 1}
	if len(prices) != 1 || prices[0] != want {
		t.Fatalf("prices = %+v, want %+v", prices, want)
	}
	if _, err := gw.Prices(context.Background(), "price_gone"); !errors.Is(err, subscription.ErrNotFound) {
		t.Errorf("a missing price is ErrNotFound: %v", err)
	}
}
