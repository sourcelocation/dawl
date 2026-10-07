// Package appstore is the App Store gateway for subscriptions bought in iOS and macOS apps: it
// verifies StoreKit 2 transactions and App Store Server Notifications V2, and reads a
// subscription's current status from the App Store Server API.
package appstore

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sourcelocation/dawl/subscription"
)

// Config holds the App Store Connect settings.
type Config struct {
	BundleID   string // the app's bundle identifier
	IssuerID   string // App Store Connect API issuer
	KeyID      string
	Key        string // in-app purchase key (.p8 PEM)
	AppAppleID int64  // the app's Apple ID; production notifications must carry it (0 skips the check)

	// Endpoints; empty means Apple's hosts.
	URL        string
	SandboxURL string
}

// Gateway talks to the App Store.
type Gateway struct {
	cfg    Config
	verify verifier
	client *http.Client

	mu     sync.Mutex
	signer *signer
}

// New builds the gateway; roots nil means Apple's real root certificate.
func New(cfg Config, roots *x509.CertPool) (*Gateway, error) {
	key, err := parseP8(cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("app store key: %w", err)
	}
	if roots == nil {
		roots = Roots()
	}
	cfg.URL = endpoint(cfg.URL, "https://api.storekit.itunes.apple.com")
	cfg.SandboxURL = endpoint(cfg.SandboxURL, "https://api.storekit-sandbox.itunes.apple.com")
	return &Gateway{
		cfg:    cfg,
		verify: verifier{roots: roots, now: time.Now},
		client: &http.Client{Timeout: 15 * time.Second},
		signer: &signer{key: key, keyID: cfg.KeyID, ttl: 20 * time.Minute, claims: jwt.MapClaims{
			"iss": cfg.IssuerID, "aud": "appstoreconnect-v1", "bid": cfg.BundleID,
		}},
	}, nil
}

func endpoint(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return strings.TrimRight(v, "/")
}

// --- signed payloads (Apple's names) ------------------------------------------------------------

type transaction struct {
	OriginalTransactionID string `json:"originalTransactionId"`
	BundleID              string `json:"bundleId"`
	ProductID             string `json:"productId"`
	ExpiresDate           int64  `json:"expiresDate"`
	RevocationDate        int64  `json:"revocationDate"`
	AppAccountToken       string `json:"appAccountToken"`
	Environment           string `json:"environment"`
	Type                  string `json:"type"`
}

type renewal struct {
	AutoRenewStatus        int   `json:"autoRenewStatus"`
	GracePeriodExpiresDate int64 `json:"gracePeriodExpiresDate"`
}

type notification struct {
	NotificationType string `json:"notificationType"`
	NotificationUUID string `json:"notificationUUID"`
	Data             struct {
		AppAppleID            int64  `json:"appAppleId"`
		BundleID              string `json:"bundleId"`
		Environment           string `json:"environment"`
		SignedTransactionInfo string `json:"signedTransactionInfo"`
		SignedRenewalInfo     string `json:"signedRenewalInfo"`
		Status                int    `json:"status"`
	} `json:"data"`
}

type statusResponse struct {
	Data []struct {
		LastTransactions []struct {
			OriginalTransactionID string `json:"originalTransactionId"`
			Status                int    `json:"status"`
			SignedTransactionInfo string `json:"signedTransactionInfo"`
			SignedRenewalInfo     string `json:"signedRenewalInfo"`
		} `json:"lastTransactions"`
	} `json:"data"`
}

// App Store subscription status values.
const (
	statusActive       = 1
	statusExpired      = 2
	statusBillingRetry = 3
	statusGracePeriod  = 4
	statusRevoked      = 5
)

// Verify checks a StoreKit 2 transaction signed by Apple, then asks the App Store for the
// subscription's current status. If Apple's API is down, the verified transaction alone decides —
// a person who just paid is never turned away by an outage (subscription.Gateway).
func (g *Gateway) Verify(ctx context.Context, signedTransaction string) (subscription.State, error) {
	var tx transaction
	if err := g.verify.verify(signedTransaction, &tx); err != nil {
		return subscription.State{}, fmt.Errorf("appstore: %w: %w", subscription.ErrUnverified, err)
	}
	if tx.BundleID != g.cfg.BundleID {
		return subscription.State{}, fmt.Errorf("appstore: %w: transaction for bundle %q", subscription.ErrUnverified, tx.BundleID)
	}
	if tx.Type != "Auto-Renewable Subscription" {
		return subscription.State{}, fmt.Errorf("appstore: %w: %s", subscription.ErrNotSubscription, tx.Type)
	}
	sub, err := g.current(ctx, tx.OriginalTransactionID)
	if errors.Is(err, subscription.ErrUnavailable) {
		return build(0, tx, renewal{AutoRenewStatus: 1}), nil
	}
	return sub, err
}

// notified verifies an App Store Server Notification V2 and returns the subscription it is about,
// as the notification describes it; nil for test and other non-subscription notifications.
func (g *Gateway) notified(signedPayload string) (*subscription.State, error) {
	var n notification
	if err := g.verify.verify(signedPayload, &n); err != nil {
		return nil, fmt.Errorf("appstore: %w: %w", subscription.ErrInvalidNotification, err)
	}
	if n.Data.BundleID != g.cfg.BundleID || (n.Data.Environment == "Production" && g.cfg.AppAppleID != 0 && n.Data.AppAppleID != g.cfg.AppAppleID) {
		return nil, fmt.Errorf("appstore: %w: notification for another app", subscription.ErrInvalidNotification)
	}
	if n.Data.SignedTransactionInfo == "" {
		return nil, nil
	}
	var tx transaction
	if err := g.verify.verify(n.Data.SignedTransactionInfo, &tx); err != nil {
		return nil, fmt.Errorf("appstore: %w: %w", subscription.ErrInvalidNotification, err)
	}
	if tx.Type != "Auto-Renewable Subscription" {
		return nil, nil
	}
	r := renewal{AutoRenewStatus: 1}
	if n.Data.SignedRenewalInfo != "" {
		if err := g.verify.verify(n.Data.SignedRenewalInfo, &r); err != nil {
			return nil, fmt.Errorf("appstore: %w: %w", subscription.ErrInvalidNotification, err)
		}
	}
	state := build(n.Data.Status, tx, r)
	return &state, nil
}

// current reads a subscription's status as the App Store has it now. Apple asks servers to try
// production first and fall back to the sandbox, which App Review and TestFlight purchases live in.
func (g *Gateway) current(ctx context.Context, originalTransactionID string) (subscription.State, error) {
	for _, base := range []string{g.cfg.URL, g.cfg.SandboxURL} {
		sub, found, err := g.status(ctx, base, originalTransactionID)
		if err != nil || found {
			return sub, err
		}
	}
	return subscription.State{}, fmt.Errorf("appstore: %w: subscription %s", subscription.ErrNotFound, originalTransactionID)
}

func (g *Gateway) status(ctx context.Context, base, original string) (subscription.State, bool, error) {
	g.mu.Lock()
	token, err := g.signer.sign(time.Now())
	g.mu.Unlock()
	if err != nil {
		return subscription.State{}, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/inApps/v1/subscriptions/"+url.PathEscape(original), nil)
	if err != nil {
		return subscription.State{}, false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := g.client.Do(req)
	if err != nil {
		return subscription.State{}, false, fmt.Errorf("appstore: %w: %w", subscription.ErrUnavailable, err)
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusNotFound:
		return subscription.State{}, false, nil
	case res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= 500:
		return subscription.State{}, false, fmt.Errorf("appstore: %w: HTTP %d", subscription.ErrUnavailable, res.StatusCode)
	case res.StatusCode != http.StatusOK:
		return subscription.State{}, false, fmt.Errorf("appstore: subscription status %s: HTTP %d", original, res.StatusCode)
	}
	var body statusResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&body); err != nil {
		return subscription.State{}, false, fmt.Errorf("appstore: decode status: %w", err)
	}
	for _, group := range body.Data {
		for _, last := range group.LastTransactions {
			if last.OriginalTransactionID != original {
				continue
			}
			var tx transaction
			r := renewal{AutoRenewStatus: 1}
			if err := g.verify.verify(last.SignedTransactionInfo, &tx); err != nil {
				return subscription.State{}, false, err
			}
			if last.SignedRenewalInfo != "" {
				if err := g.verify.verify(last.SignedRenewalInfo, &r); err != nil {
					return subscription.State{}, false, err
				}
			}
			return build(last.Status, tx, r), true, nil
		}
	}
	return subscription.State{}, false, nil
}

// build normalises App Store state. status 0 means "unknown": the signed transaction alone decides.
func build(status int, tx transaction, r renewal) subscription.State {
	out := subscription.State{
		Provider: subscription.AppStore, ProviderRef: tx.OriginalTransactionID, ProductID: tx.ProductID,
		AutoRenew: r.AutoRenewStatus == 1, Environment: "production", Account: tx.AppAccountToken,
	}
	if tx.Environment == "Sandbox" || tx.Environment == "Xcode" {
		out.Environment = "sandbox"
	}
	if tx.ExpiresDate > 0 {
		end := time.UnixMilli(tx.ExpiresDate).UTC()
		out.CurrentPeriodEnd = &end
	}
	if status == 0 {
		status = statusExpired
		if out.CurrentPeriodEnd != nil && out.CurrentPeriodEnd.After(time.Now()) {
			status = statusActive
		}
	}
	switch {
	case tx.RevocationDate > 0 || status == statusRevoked:
		out.Status, out.AutoRenew = subscription.StatusRevoked, false
	case status == statusActive && !out.AutoRenew:
		out.Status = subscription.StatusCanceled
	case status == statusActive:
		out.Status = subscription.StatusActive
	case status == statusGracePeriod:
		out.Status = subscription.StatusInGrace
		if r.GracePeriodExpiresDate > 0 {
			end := time.UnixMilli(r.GracePeriodExpiresDate).UTC()
			out.CurrentPeriodEnd = &end
		}
	case status == statusBillingRetry:
		out.Status = subscription.StatusOnHold
	default:
		out.Status, out.AutoRenew = subscription.StatusExpired, false
	}
	return out
}

// Notification verifies an App Store Server Notification V2 request and reads the subscription it
// is about from the App Store; the notification's own copy stands only when the App Store no longer
// knows the subscription (subscription.Gateway).
func (g *Gateway) Notification(ctx context.Context, r *http.Request) (*subscription.State, error) {
	var body struct {
		SignedPayload string `json:"signedPayload"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || body.SignedPayload == "" {
		return nil, fmt.Errorf("appstore: %w: notification body", subscription.ErrMalformed)
	}
	notified, err := g.notified(body.SignedPayload)
	if err != nil || notified == nil {
		return nil, err
	}
	state, err := g.current(ctx, notified.ProviderRef)
	switch {
	case errors.Is(err, subscription.ErrNotFound):
		return notified, nil
	case err != nil:
		return nil, err
	}
	return &state, nil
}
