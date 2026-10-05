package stripe

import (
	"encoding/json"
	"errors"
	"fmt"
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

func TestWebhookDecodesSubscriptionState(t *testing.T) {
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
			payload, header := event(t, "customer.subscription.updated", stripeSubscription(c.status, c.ending, end))
			hook, err := gateway().ParseWebhook(payload, header)
			if err != nil {
				t.Fatal(err)
			}
			sub := hook.Subscription
			if hook.EventID != "evt_1" || hook.Customer != "cus_1" || sub == nil {
				t.Fatalf("hook = %+v", hook)
			}
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

func TestWebhookRejectsForgedSignatures(t *testing.T) {
	payload, _ := event(t, "customer.subscription.updated", stripeSubscription("active", false, 1))
	forged := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: payload, Secret: "whsec_attacker"})
	if _, err := gateway().ParseWebhook(payload, forged.Header); !errors.Is(err, subscription.ErrInvalidNotification) {
		t.Fatalf("err = %v", err)
	}
}

func TestOtherEventsAreAcknowledgedWithoutState(t *testing.T) {
	payload, header := event(t, "invoice.paid", map[string]any{"id": "in_1", "object": "invoice"})
	hook, err := gateway().ParseWebhook(payload, header)
	if err != nil || hook.EventID != "evt_1" || hook.Subscription != nil {
		t.Fatalf("hook=%+v err=%v", hook, err)
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
