package discord

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/sourcelocation/dawl/subscription"
)

const (
	app   = "1000000000000000001"
	user  = "1000000000000000002"
	guild = "1000000000000000003"
	sku   = "1000000000000000004"
)

type discordServer struct {
	*httptest.Server
	entitlement map[string]any // what Discord has now; nil: it doesn't know it
	status      int            // overrides 200
	reads       int
}

func newDiscord(t *testing.T) (*Gateway, *discordServer, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &discordServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bot token" || r.URL.Path != "/applications/"+app+"/entitlements/e1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		s.reads++
		switch {
		case s.status != 0:
			w.WriteHeader(s.status)
		case s.entitlement == nil:
			w.WriteHeader(http.StatusNotFound)
		default:
			_ = json.NewEncoder(w).Encode(s.entitlement)
		}
	}))
	t.Cleanup(s.Close)
	gw, err := New(Config{AppID: app, BotToken: "token", PublicKey: hex.EncodeToString(pub), APIBase: s.URL})
	if err != nil {
		t.Fatal(err)
	}
	return gw, s, priv
}

func guildEntitlement(endsAt any) map[string]any {
	return map[string]any{"id": "e1", "sku_id": sku, "application_id": app, "user_id": user, "guild_id": guild,
		"type": 8, "deleted": false, "starts_at": "2026-10-01T00:00:00Z", "ends_at": endsAt}
}

// request is a Webhook Events request, signed with key.
func request(t *testing.T, key ed25519.PrivateKey, body map[string]any) *http.Request {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	r := httptest.NewRequest(http.MethodPost, "/webhooks/discord", bytes.NewReader(raw))
	r.Header.Set("X-Signature-Timestamp", ts)
	r.Header.Set("X-Signature-Ed25519", hex.EncodeToString(ed25519.Sign(key, append([]byte(ts), raw...))))
	return r
}

func event(typ string, data map[string]any) map[string]any {
	return map[string]any{"version": 1, "application_id": app, "type": 1,
		"event": map[string]any{"type": typ, "timestamp": "2026-10-09T12:00:00Z", "data": data}}
}

func TestEntitlementsAreNormalised(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	soon, past := now.Add(time.Hour), now.Add(-time.Hour)
	cases := []struct {
		name   string
		e      entitlement
		status subscription.Status
		end    *time.Time
		env    string
	}{
		{"active", entitlement{ID: "e1", Type: 8}, subscription.StatusActive, &subscription.Forever, "production"},
		{"ending", entitlement{ID: "e1", Type: 8, EndsAt: &soon}, subscription.StatusCanceled, &soon, "production"},
		{"ended", entitlement{ID: "e1", Type: 8, EndsAt: &past}, subscription.StatusExpired, &past, "production"},
		{"refunded", entitlement{ID: "e1", Type: 8, Deleted: true}, subscription.StatusRevoked, nil, "production"},
		{"test mode", entitlement{ID: "e1", Type: testModePurchase}, subscription.StatusActive, &subscription.Forever, "sandbox"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := toState(c.e, now)
			if s.Status != c.status || s.Environment != c.env || (s.CurrentPeriodEnd == nil) != (c.end == nil) ||
				(c.end != nil && !s.CurrentPeriodEnd.Equal(*c.end)) {
				t.Fatalf("got %s %s until %v, want %s %s until %v", s.Status, s.Environment, s.CurrentPeriodEnd, c.status, c.env, c.end)
			}
		})
	}
}

func TestNotificationsReadTheEntitlementAgain(t *testing.T) {
	gw, d, key := newDiscord(t)
	d.entitlement = guildEntitlement(nil)
	// The event carries an older copy; the gateway trusts only what Discord has now.
	state, err := gw.Notification(context.Background(), request(t, key, event("ENTITLEMENT_CREATE", guildEntitlement("2026-10-01T00:00:00Z"))))
	if err != nil {
		t.Fatal(err)
	}
	if d.reads != 1 || state.Provider != subscription.Discord || state.ProviderRef != "e1" || state.ProductID != sku ||
		state.Account != user || state.Covers != guild || !state.Entitles(time.Now()) {
		t.Fatalf("a guild subscription bought by a user, active: %+v", state)
	}
	if until, ok := state.Until(); !ok || !until.Equal(subscription.Forever) {
		t.Errorf("until Discord ends it: %v %v", until, ok)
	}

	d.entitlement = guildEntitlement(time.Now().Add(-time.Minute).Format(time.RFC3339))
	state, err = gw.Notification(context.Background(), request(t, key, event("ENTITLEMENT_UPDATE", guildEntitlement(nil))))
	if err != nil || state.Status != subscription.StatusExpired || state.Entitles(time.Now()) {
		t.Fatalf("an ended subscription grants nothing: %+v %v", state, err)
	}

	d.entitlement = nil
	state, err = gw.Notification(context.Background(), request(t, key, event("ENTITLEMENT_DELETE", guildEntitlement(nil))))
	if err != nil || state.Status != subscription.StatusRevoked || state.Covers != guild {
		t.Fatalf("a deleted entitlement Discord no longer returns is revoked: %+v %v", state, err)
	}
	if _, err := gw.Notification(context.Background(), request(t, key, event("ENTITLEMENT_UPDATE", guildEntitlement(nil)))); !errors.Is(err, subscription.ErrNotFound) {
		t.Errorf("one that isn't deleted is an error, so Discord delivers it again: %v", err)
	}
}

func TestNotificationsAreVerified(t *testing.T) {
	gw, d, key := newDiscord(t)
	d.entitlement = guildEntitlement(nil)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := gw.Notification(context.Background(), request(t, other, event("ENTITLEMENT_CREATE", guildEntitlement(nil)))); !errors.Is(err, subscription.ErrInvalidNotification) {
		t.Errorf("signed by another key: %v", err)
	}
	r := request(t, key, event("ENTITLEMENT_CREATE", guildEntitlement(nil)))
	r.Header.Set("X-Signature-Timestamp", "1")
	if _, err := gw.Notification(context.Background(), r); !errors.Is(err, subscription.ErrInvalidNotification) {
		t.Errorf("with another timestamp: %v", err)
	}
	foreign := event("ENTITLEMENT_CREATE", guildEntitlement(nil))
	foreign["application_id"] = "1"
	if _, err := gw.Notification(context.Background(), request(t, key, foreign)); !errors.Is(err, subscription.ErrInvalidNotification) {
		t.Errorf("for another application: %v", err)
	}
	if d.reads != 0 {
		t.Errorf("nothing unverified reaches Discord's API: %d reads", d.reads)
	}

	webhook := subscription.Webhook(gw, func(context.Context, subscription.State) error {
		t.Error("nothing to save")
		return nil
	})
	for name, body := range map[string]map[string]any{
		"ping":  {"version": 1, "application_id": app, "type": 0},
		"other": event("APPLICATION_AUTHORIZED", map[string]any{"user": map[string]any{"id": user}}),
	} {
		w := httptest.NewRecorder()
		webhook.ServeHTTP(w, request(t, key, body))
		if w.Code != http.StatusNoContent || w.Header().Get("Content-Type") == "" {
			t.Errorf("a %s gets 204 with a content type: %d %q", name, w.Code, w.Header().Get("Content-Type"))
		}
	}
	w := httptest.NewRecorder()
	webhook.ServeHTTP(w, request(t, other, map[string]any{"version": 1, "application_id": app, "type": 0}))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Discord's probe with a bad signature gets 401: %d", w.Code)
	}
}

func TestVerify(t *testing.T) {
	gw, d, _ := newDiscord(t)
	if _, err := gw.Verify(context.Background(), "e1"); !errors.Is(err, subscription.ErrUnverified) {
		t.Errorf("an entitlement Discord doesn't know: %v", err)
	}
	d.entitlement = guildEntitlement(nil)
	d.entitlement["application_id"] = "1"
	if _, err := gw.Verify(context.Background(), "e1"); !errors.Is(err, subscription.ErrUnverified) {
		t.Errorf("another application's: %v", err)
	}
	d.status = http.StatusServiceUnavailable
	if _, err := gw.Verify(context.Background(), "e1"); !errors.Is(err, subscription.ErrUnavailable) {
		t.Errorf("Discord down: %v", err)
	}
	d.status, d.entitlement["application_id"] = 0, app
	if s, err := gw.Verify(context.Background(), "e1"); err != nil || !s.Entitles(time.Now()) {
		t.Errorf("an active one: %+v %v", s, err)
	}
}

func TestNewChecksThePublicKey(t *testing.T) {
	if _, err := New(Config{PublicKey: "nothex"}); err == nil {
		t.Error("a public key that isn't hex")
	}
}
