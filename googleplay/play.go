// Package googleplay is the Google Play billing gateway: subscription state from the Android
// Publisher API and Real-time Developer Notifications delivered by Pub/Sub push.
package googleplay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2/google"

	"github.com/sourcelocation/dawl/internal/jwks"
	"github.com/sourcelocation/dawl/subscription"
)

// Config holds the Play Console settings.
type Config struct {
	PackageName       string
	ServiceAccountKey string // JSON key of a service account with access to the Play Console
	PubSubAudience    string // audience configured on the push subscription
	PubSubAccount     string // service account the push subscription authenticates as

	APIBase  string // default https://androidpublisher.googleapis.com
	CertsURL string // default https://www.googleapis.com/oauth2/v3/certs
}

// Gateway talks to Google Play.
type Gateway struct {
	cfg    Config
	client *http.Client
	certs  *jwks.Set
}

// New builds the gateway. client nil means: authenticate as the configured service account.
func New(ctx context.Context, cfg Config, client *http.Client) (*Gateway, error) {
	if client == nil {
		jwtCfg, err := google.JWTConfigFromJSON([]byte(cfg.ServiceAccountKey), "https://www.googleapis.com/auth/androidpublisher")
		if err != nil {
			return nil, fmt.Errorf("googleplay: service account key: %w", err)
		}
		client = jwtCfg.Client(ctx)
		client.Timeout = 15 * time.Second
	}
	if cfg.APIBase == "" {
		cfg.APIBase = "https://androidpublisher.googleapis.com"
	}
	if cfg.CertsURL == "" {
		cfg.CertsURL = "https://www.googleapis.com/oauth2/v3/certs"
	}
	return &Gateway{cfg: cfg, client: client, certs: jwks.New(cfg.CertsURL, nil)}, nil
}

// subscriptionV2 is the part of SubscriptionPurchaseV2 this gateway reads.
type subscriptionV2 struct {
	SubscriptionState    string    `json:"subscriptionState"`
	AcknowledgementState string    `json:"acknowledgementState"`
	TestPurchase         *struct{} `json:"testPurchase"`
	LineItems            []struct {
		ProductID        string `json:"productId"`
		ExpiryTime       string `json:"expiryTime"`
		AutoRenewingPlan *struct {
			AutoRenewEnabled bool `json:"autoRenewEnabled"`
		} `json:"autoRenewingPlan"`
	} `json:"lineItems"`
	ExternalAccountIdentifiers *struct {
		ObfuscatedExternalAccountID string `json:"obfuscatedExternalAccountId"`
	} `json:"externalAccountIdentifiers"`
}

// VerifySubscription reads a subscription by purchase token (purchases.subscriptionsv2.get).
func (g *Gateway) VerifySubscription(ctx context.Context, purchaseToken string) (subscription.State, error) {
	var sub subscriptionV2
	status, err := g.call(ctx, http.MethodGet, "/purchases/subscriptionsv2/tokens/"+url.PathEscape(purchaseToken), nil, &sub)
	switch {
	case err != nil:
		return subscription.State{}, err
	case status == http.StatusNotFound || status == http.StatusBadRequest || status == http.StatusGone:
		return subscription.State{}, fmt.Errorf("googleplay: %w: HTTP %d", subscription.ErrUnverified, status)
	case status != http.StatusOK:
		return subscription.State{}, fmt.Errorf("googleplay: subscription: HTTP %d", status)
	}
	return toState(purchaseToken, sub), nil
}

// Acknowledge confirms a purchase; Play refunds purchases left unacknowledged for three days.
func (g *Gateway) Acknowledge(ctx context.Context, purchaseToken, productID string) error {
	path := "/purchases/subscriptions/" + url.PathEscape(productID) + "/tokens/" + url.PathEscape(purchaseToken) + ":acknowledge"
	status, err := g.call(ctx, http.MethodPost, path, map[string]any{}, nil)
	if err != nil {
		return err
	}
	if status == http.StatusOK || status == http.StatusNoContent {
		return nil
	}
	// Play answers 400 when the purchase was acknowledged already; confirm before giving up.
	var sub subscriptionV2
	if s, err := g.call(ctx, http.MethodGet, "/purchases/subscriptionsv2/tokens/"+url.PathEscape(purchaseToken), nil, &sub); err == nil &&
		s == http.StatusOK && sub.AcknowledgementState == "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED" {
		return nil
	}
	return fmt.Errorf("googleplay: acknowledge: HTTP %d", status)
}

func (g *Gateway) call(ctx context.Context, method, path string, body, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(raw)
	}
	endpoint := g.cfg.APIBase + "/androidpublisher/v3/applications/" + url.PathEscape(g.cfg.PackageName) + path
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := g.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("googleplay: %w: %w", subscription.ErrUnavailable, err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 500 || res.StatusCode == http.StatusTooManyRequests {
		return 0, fmt.Errorf("googleplay: %w: HTTP %d", subscription.ErrUnavailable, res.StatusCode)
	}
	if out != nil && res.StatusCode == http.StatusOK {
		if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(out); err != nil {
			return 0, fmt.Errorf("googleplay: decode: %w", err)
		}
	}
	return res.StatusCode, nil
}

// ParseNotification verifies a Pub/Sub push (Google-signed OIDC token) and returns the message id
// and the purchase token of a subscription or voided-purchase notification (empty for test and
// one-time-product notifications).
func (g *Gateway) ParseNotification(ctx context.Context, authorization string, body []byte) (string, string, error) {
	token, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok {
		return "", "", fmt.Errorf("googleplay: %w: no bearer token", subscription.ErrInvalidNotification)
	}
	var claims struct {
		jwt.RegisteredClaims
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if _, err := jwt.ParseWithClaims(token, &claims, g.certs.Keyfunc(ctx),
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(g.cfg.PubSubAudience), jwt.WithExpirationRequired(), jwt.WithLeeway(time.Minute)); err != nil {
		return "", "", fmt.Errorf("googleplay: %w: %w", subscription.ErrInvalidNotification, err)
	}
	if (claims.Issuer != "https://accounts.google.com" && claims.Issuer != "accounts.google.com") || !claims.EmailVerified || claims.Email != g.cfg.PubSubAccount {
		return "", "", fmt.Errorf("googleplay: %w: pushed by %q", subscription.ErrInvalidNotification, claims.Email)
	}
	var push struct {
		Message struct {
			Data      string `json:"data"`
			MessageID string `json:"messageId"`
		} `json:"message"`
	}
	if err := json.Unmarshal(body, &push); err != nil || push.Message.MessageID == "" {
		return "", "", fmt.Errorf("googleplay: %w: push envelope", subscription.ErrMalformed)
	}
	raw, err := base64.StdEncoding.DecodeString(push.Message.Data)
	if err != nil {
		return "", "", fmt.Errorf("googleplay: %w: %w", subscription.ErrMalformed, err)
	}
	var n struct {
		PackageName              string `json:"packageName"`
		SubscriptionNotification *struct {
			PurchaseToken string `json:"purchaseToken"`
		} `json:"subscriptionNotification"`
		VoidedPurchaseNotification *struct {
			PurchaseToken string `json:"purchaseToken"`
			ProductType   int    `json:"productType"` // 1 = subscription
		} `json:"voidedPurchaseNotification"`
	}
	if err := json.Unmarshal(raw, &n); err != nil {
		return "", "", fmt.Errorf("googleplay: %w: %w", subscription.ErrMalformed, err)
	}
	if n.PackageName != g.cfg.PackageName {
		return "", "", fmt.Errorf("googleplay: %w: notification for %q", subscription.ErrInvalidNotification, n.PackageName)
	}
	switch {
	case n.SubscriptionNotification != nil:
		return push.Message.MessageID, n.SubscriptionNotification.PurchaseToken, nil
	case n.VoidedPurchaseNotification != nil && n.VoidedPurchaseNotification.ProductType == 1:
		return push.Message.MessageID, n.VoidedPurchaseNotification.PurchaseToken, nil
	default: // test and one-time-product notifications
		return push.Message.MessageID, "", nil
	}
}

// toState normalises Play's subscription states.
func toState(token string, s subscriptionV2) subscription.State {
	out := subscription.State{Provider: subscription.GooglePlay, ProviderRef: token, Environment: "production"}
	if s.TestPurchase != nil {
		out.Environment = "sandbox"
	}
	for _, item := range s.LineItems {
		if out.ProductID == "" {
			out.ProductID = item.ProductID
		}
		if item.AutoRenewingPlan != nil && item.AutoRenewingPlan.AutoRenewEnabled {
			out.AutoRenew = true
		}
		if t, err := time.Parse(time.RFC3339Nano, item.ExpiryTime); err == nil && (out.CurrentPeriodEnd == nil || t.After(*out.CurrentPeriodEnd)) {
			end := t.UTC()
			out.CurrentPeriodEnd = &end
		}
	}
	switch s.SubscriptionState {
	case "SUBSCRIPTION_STATE_ACTIVE":
		out.Status = subscription.StatusActive
	case "SUBSCRIPTION_STATE_CANCELED":
		out.Status, out.AutoRenew = subscription.StatusCanceled, false
	case "SUBSCRIPTION_STATE_IN_GRACE_PERIOD":
		out.Status = subscription.StatusInGrace
	case "SUBSCRIPTION_STATE_ON_HOLD", "SUBSCRIPTION_STATE_PENDING":
		out.Status = subscription.StatusOnHold
	case "SUBSCRIPTION_STATE_PAUSED":
		out.Status = subscription.StatusPaused
	default: // EXPIRED, PENDING_PURCHASE_CANCELED, UNSPECIFIED
		out.Status, out.AutoRenew = subscription.StatusExpired, false
	}
	if s.ExternalAccountIdentifiers != nil {
		out.Account = s.ExternalAccountIdentifiers.ObfuscatedExternalAccountID
	}
	return out
}
