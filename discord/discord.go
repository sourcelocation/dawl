// Package discord is the gateway for Discord's app subscriptions: entitlements read from Discord's
// API, and Webhook Events (ENTITLEMENT_CREATE, ENTITLEMENT_UPDATE, ENTITLEMENT_DELETE) verified by
// their Ed25519 signature.
//
// Discord grants a subscription's entitlement with no end, and sets one only when the subscription
// ends: an active entitlement's period end is subscription.Forever. Renewals and cancellations send
// no entitlement event, since the entitlement carries on until Discord ends it; its webhook events
// are therefore all an app needs to keep access right. Every kind of entitlement maps the same way
// (subscriptions, one-time purchases, gifts and test entitlements): apps tell them apart by SKU.
package discord

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/sourcelocation/dawl/subscription"
)

// Config holds the Discord application's settings, from the developer portal.
type Config struct {
	AppID     string // the application's id
	BotToken  string // reads entitlements
	PublicKey string // hex; verifies webhook events, as it does interactions
	APIBase   string // default https://discord.com/api/v10
}

// Gateway talks to Discord.
type Gateway struct {
	cfg    Config
	key    ed25519.PublicKey
	client *http.Client
}

// New builds the gateway.
func New(cfg Config) (*Gateway, error) {
	key, err := hex.DecodeString(cfg.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("discord: the public key isn't %d bytes of hex", ed25519.PublicKeySize)
	}
	if cfg.APIBase == "" {
		cfg.APIBase = "https://discord.com/api/v10"
	}
	return &Gateway{cfg: cfg, key: key, client: &http.Client{Timeout: 15 * time.Second}}, nil
}

// entitlement is the part of Discord's entitlement object this gateway reads.
type entitlement struct {
	ID            string     `json:"id"`
	SKUID         string     `json:"sku_id"`
	ApplicationID string     `json:"application_id"`
	UserID        string     `json:"user_id"`
	GuildID       string     `json:"guild_id"`
	Type          int        `json:"type"`
	Deleted       bool       `json:"deleted"`
	EndsAt        *time.Time `json:"ends_at"`
}

// testModePurchase is an entitlement bought in the application's test mode, or made by the test
// entitlement endpoint.
const testModePurchase = 4

// current reads an entitlement as Discord has it now.
func (g *Gateway) current(ctx context.Context, id string) (entitlement, error) {
	endpoint := g.cfg.APIBase + "/applications/" + url.PathEscape(g.cfg.AppID) + "/entitlements/" + url.PathEscape(id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return entitlement{}, err
	}
	req.Header.Set("Authorization", "Bot "+g.cfg.BotToken)
	res, err := g.client.Do(req)
	if err != nil {
		return entitlement{}, fmt.Errorf("discord: %w: %w", subscription.ErrUnavailable, err)
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusNotFound:
		return entitlement{}, fmt.Errorf("discord: %w: entitlement %s", subscription.ErrNotFound, id)
	case res.StatusCode >= 500 || res.StatusCode == http.StatusTooManyRequests:
		return entitlement{}, fmt.Errorf("discord: %w: HTTP %d", subscription.ErrUnavailable, res.StatusCode)
	case res.StatusCode != http.StatusOK:
		return entitlement{}, fmt.Errorf("discord: entitlement: HTTP %d", res.StatusCode)
	}
	var e entitlement
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&e); err != nil {
		return entitlement{}, fmt.Errorf("discord: decode: %w", err)
	}
	if e.ApplicationID != g.cfg.AppID {
		return entitlement{}, fmt.Errorf("discord: %w: entitlement of application %s", subscription.ErrUnverified, e.ApplicationID)
	}
	return e, nil
}

// toState normalises an entitlement: active with no end, ending once Discord sets one, revoked when
// deleted (refunded or removed).
func toState(e entitlement, now time.Time) subscription.State {
	out := subscription.State{Provider: subscription.Discord, ProviderRef: e.ID, ProductID: e.SKUID, Environment: "production",
		Account: e.UserID, Covers: e.GuildID}
	if e.Type == testModePurchase {
		out.Environment = "sandbox"
	}
	switch {
	case e.Deleted:
		out.Status = subscription.StatusRevoked
	case e.EndsAt == nil:
		out.Status, out.CurrentPeriodEnd = subscription.StatusActive, &subscription.Forever
	default:
		end := e.EndsAt.UTC()
		out.Status, out.CurrentPeriodEnd = subscription.StatusCanceled, &end // entitled until it ends
		if !now.Before(end) {
			out.Status = subscription.StatusExpired
		}
	}
	return out
}

// Verify reads an entitlement by id (subscription.Gateway).
func (g *Gateway) Verify(ctx context.Context, proof string) (subscription.State, error) {
	e, err := g.current(ctx, proof)
	if errors.Is(err, subscription.ErrNotFound) {
		return subscription.State{}, fmt.Errorf("discord: %w: %w", subscription.ErrUnverified, err)
	}
	if err != nil {
		return subscription.State{}, err
	}
	return toState(e, time.Now()), nil
}

// webhookEvent is a Webhook Events request: a ping (type 0) or an event (type 1).
type webhookEvent struct {
	Type          int    `json:"type"`
	ApplicationID string `json:"application_id"`
	Event         *struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	} `json:"event"`
}

// Notification verifies a Webhook Events request by its Ed25519 signature and reads the
// entitlement it is about from Discord (subscription.Gateway). Pings and other events return nil.
// A deleted entitlement Discord no longer returns is revoked.
func (g *Gateway) Notification(ctx context.Context, r *http.Request) (*subscription.State, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("discord: %w: %w", subscription.ErrMalformed, err)
	}
	signature, err := hex.DecodeString(r.Header.Get("X-Signature-Ed25519"))
	timestamp := r.Header.Get("X-Signature-Timestamp")
	if err != nil || timestamp == "" || !ed25519.Verify(g.key, append([]byte(timestamp), body...), signature) {
		return nil, fmt.Errorf("discord: %w: bad signature", subscription.ErrInvalidNotification)
	}
	var w webhookEvent
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("discord: %w: %w", subscription.ErrMalformed, err)
	}
	if w.ApplicationID != g.cfg.AppID {
		return nil, fmt.Errorf("discord: %w: event for application %s", subscription.ErrInvalidNotification, w.ApplicationID)
	}
	if w.Type == 0 || w.Event == nil {
		return nil, nil // a ping
	}
	switch w.Event.Type {
	case "ENTITLEMENT_CREATE", "ENTITLEMENT_UPDATE", "ENTITLEMENT_DELETE":
	default:
		return nil, nil
	}
	var sent entitlement
	if err := json.Unmarshal(w.Event.Data, &sent); err != nil || sent.ID == "" {
		return nil, fmt.Errorf("discord: %w: entitlement event without an entitlement", subscription.ErrMalformed)
	}
	e, err := g.current(ctx, sent.ID)
	if errors.Is(err, subscription.ErrNotFound) && w.Event.Type == "ENTITLEMENT_DELETE" {
		e, err = sent, nil
		e.Deleted = true
	}
	if err != nil {
		return nil, err
	}
	state := toState(e, time.Now())
	return &state, nil
}
