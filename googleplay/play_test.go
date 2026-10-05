package googleplay

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sourcelocation/dawl/subscription"
)

const (
	pkg     = "com.example.app"
	pushSA  = "play-push@example.iam.gserviceaccount.com"
	pushAud = "https://api.example.test/billing/google/notifications"
	account = "0199a2b4-0000-7000-8000-0000000000aa"
)

type playServer struct {
	*httptest.Server
	key   *rsa.PrivateKey
	state string
	acked bool
	ackOK bool
}

func newPlay(t *testing.T) (*Gateway, *playServer) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := &playServer{key: key, state: "SUBSCRIPTION_STATE_ACTIVE", ackOK: true}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/certs":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
				"kid": "g1", "kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}})
		case strings.HasSuffix(r.URL.Path, "/purchases/subscriptionsv2/tokens/tok-1"):
			ack := "ACKNOWLEDGEMENT_STATE_PENDING"
			if s.acked {
				ack = "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"subscriptionState": s.state, "acknowledgementState": ack, "testPurchase": map[string]any{},
				"lineItems": []any{map[string]any{
					"productId": "app_pro", "expiryTime": "2026-11-02T10:00:00.123Z", "autoRenewingPlan": map[string]any{"autoRenewEnabled": true},
				}},
				"externalAccountIdentifiers": map[string]any{"obfuscatedExternalAccountId": account},
			})
		case strings.HasSuffix(r.URL.Path, "/purchases/subscriptions/app_pro/tokens/tok-1:acknowledge") && r.Method == http.MethodPost:
			if !s.ackOK {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.acked = true
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Close)
	play, err := New(context.Background(), Config{PackageName: pkg, PubSubAudience: pushAud, PubSubAccount: pushSA, APIBase: s.URL, CertsURL: s.URL + "/certs"}, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	return play, s
}

func TestVerifySubscriptionMapsStates(t *testing.T) {
	play, srv := newPlay(t)
	ctx := context.Background()
	for state, want := range map[string]subscription.Status{
		"SUBSCRIPTION_STATE_ACTIVE":                    subscription.StatusActive,
		"SUBSCRIPTION_STATE_CANCELED":                  subscription.StatusCanceled,
		"SUBSCRIPTION_STATE_IN_GRACE_PERIOD":           subscription.StatusInGrace,
		"SUBSCRIPTION_STATE_ON_HOLD":                   subscription.StatusOnHold,
		"SUBSCRIPTION_STATE_PAUSED":                    subscription.StatusPaused,
		"SUBSCRIPTION_STATE_PENDING":                   subscription.StatusOnHold,
		"SUBSCRIPTION_STATE_EXPIRED":                   subscription.StatusExpired,
		"SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED": subscription.StatusExpired,
	} {
		srv.state = state
		sub, err := play.VerifySubscription(ctx, "tok-1")
		if err != nil || sub.Status != want {
			t.Fatalf("%s → %+v %v", state, sub, err)
		}
		if sub.Provider != subscription.GooglePlay || sub.ProviderRef != "tok-1" || sub.ProductID != "app_pro" || sub.Environment != "sandbox" || sub.Account != account {
			t.Fatalf("sub = %+v", sub)
		}
		if want := time.Date(2026, 11, 2, 10, 0, 0, 123e6, time.UTC); !sub.CurrentPeriodEnd.Equal(want) {
			t.Fatalf("expiry %v", sub.CurrentPeriodEnd)
		}
	}
	if _, err := play.VerifySubscription(ctx, "forged"); !errors.Is(err, subscription.ErrUnverified) {
		t.Fatalf("unknown token: %v", err)
	}
}

func TestAcknowledgeIsIdempotent(t *testing.T) {
	play, srv := newPlay(t)
	ctx := context.Background()
	if err := play.Acknowledge(ctx, "tok-1", "app_pro"); err != nil || !srv.acked {
		t.Fatalf("ack: %v", err)
	}
	srv.ackOK = false // Play rejects a second acknowledgement
	if err := play.Acknowledge(ctx, "tok-1", "app_pro"); err != nil {
		t.Fatalf("second ack must succeed: %v", err)
	}
	srv.acked = false
	if err := play.Acknowledge(ctx, "tok-1", "app_pro"); err == nil {
		t.Fatal("failed, unacknowledged purchase must report an error")
	}
}

func (s *playServer) push(t *testing.T, claims jwt.MapClaims, notification map[string]any) (string, []byte) {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "g1"
	signed, err := tok.SignedString(s.key)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(notification)
	body, _ := json.Marshal(map[string]any{"message": map[string]any{"data": base64.StdEncoding.EncodeToString(data), "messageId": "m-1"}})
	return "Bearer " + signed, body
}

func TestParseNotificationVerifiesThePush(t *testing.T) {
	play, srv := newPlay(t)
	ctx := context.Background()
	valid := jwt.MapClaims{"iss": "https://accounts.google.com", "aud": pushAud, "email": pushSA, "email_verified": true, "exp": time.Now().Add(time.Hour).Unix()}
	sub := map[string]any{"packageName": pkg, "subscriptionNotification": map[string]any{"notificationType": 4, "purchaseToken": "tok-1"}}

	auth, body := srv.push(t, valid, sub)
	if id, token, err := play.ParseNotification(ctx, auth, body); err != nil || id != "m-1" || token != "tok-1" {
		t.Fatalf("%s %s %v", id, token, err)
	}
	voided := map[string]any{"packageName": pkg, "voidedPurchaseNotification": map[string]any{"purchaseToken": "tok-2", "productType": 1}}
	auth, body = srv.push(t, valid, voided)
	if _, token, err := play.ParseNotification(ctx, auth, body); err != nil || token != "tok-2" {
		t.Fatalf("voided: %s %v", token, err)
	}
	test := map[string]any{"packageName": pkg, "testNotification": map[string]any{"version": "1.0"}}
	auth, body = srv.push(t, valid, test)
	if _, token, err := play.ParseNotification(ctx, auth, body); err != nil || token != "" {
		t.Fatalf("test: %s %v", token, err)
	}

	for name, claims := range map[string]jwt.MapClaims{
		"other account":  {"iss": "https://accounts.google.com", "aud": pushAud, "email": "evil@example.com", "email_verified": true, "exp": time.Now().Add(time.Hour).Unix()},
		"other audience": {"iss": "https://accounts.google.com", "aud": "https://evil.test", "email": pushSA, "email_verified": true, "exp": time.Now().Add(time.Hour).Unix()},
		"expired":        {"iss": "https://accounts.google.com", "aud": pushAud, "email": pushSA, "email_verified": true, "exp": time.Now().Add(-time.Hour).Unix()},
	} {
		auth, body := srv.push(t, claims, sub)
		if _, _, err := play.ParseNotification(ctx, auth, body); !errors.Is(err, subscription.ErrInvalidNotification) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	other := map[string]any{"packageName": "com.example.other", "subscriptionNotification": map[string]any{"purchaseToken": "tok-1"}}
	auth, body = srv.push(t, valid, other)
	if _, _, err := play.ParseNotification(ctx, auth, body); !errors.Is(err, subscription.ErrInvalidNotification) {
		t.Errorf("other package accepted: %v", err)
	}
	if _, _, err := play.ParseNotification(ctx, "", body); !errors.Is(err, subscription.ErrInvalidNotification) {
		t.Errorf("missing token accepted: %v", err)
	}
	auth, _ = srv.push(t, valid, sub)
	if _, _, err := play.ParseNotification(ctx, auth, []byte(`{"message":{}}`)); !errors.Is(err, subscription.ErrMalformed) {
		t.Errorf("malformed push accepted: %v", err)
	}
}
