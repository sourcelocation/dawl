package appstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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

// pki mimics Apple's hierarchy: root → WWDR intermediate (marker OID) → App Store leaf (marker OID).
type pki struct {
	roots   *x509.CertPool
	leafKey *ecdsa.PrivateKey
	x5c     []string
}

func newPKI(t *testing.T, leafOID, intermediateOID asn1.ObjectIdentifier) pki {
	t.Helper()
	mk := func(tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, key
	}
	now := time.Now()
	ext := func(oid asn1.ObjectIdentifier) []pkix.Extension {
		if oid == nil {
			return nil
		}
		return []pkix.Extension{{Id: oid, Value: []byte{0x05, 0x00}}}
	}
	root, rootKey := mk(&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour * 24 * 365),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil, nil)
	inter, interKey := mk(&x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test WWDR"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour * 24 * 365),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, ExtraExtensions: ext(intermediateOID)}, root, rootKey)
	leaf, leafKey := mk(&x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Test App Store"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour * 24 * 365),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: ext(leafOID)}, inter, interKey)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	enc := base64.StdEncoding.EncodeToString
	return pki{roots: pool, leafKey: leafKey, x5c: []string{enc(leaf.Raw), enc(inter.Raw), enc(root.Raw)}}
}

func (p pki) sign(t *testing.T, payload any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "ES256", "x5c": p.x5c})
	body, _ := json.Marshal(payload)
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, p.leafKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func p8(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), key
}

const (
	bundle  = "com.example.app"
	account = "0199a2b4-0000-7000-8000-0000000000aa"
)

func tx(expires time.Time) map[string]any {
	return map[string]any{
		"originalTransactionId": "2000000001", "bundleId": bundle, "productId": "com.example.app.pro.yearly",
		"expiresDate": expires.UnixMilli(), "appAccountToken": account, "environment": "Production",
		"type": "Auto-Renewable Subscription", "signedDate": time.Now().UnixMilli(),
	}
}

func TestVerifierAcceptsOnlyApplesChain(t *testing.T) {
	good := newPKI(t, oidAppStoreLeaf, oidAppleWWDRIntermediate)
	v := verifier{roots: good.roots, now: time.Now}
	jws := good.sign(t, map[string]any{"hello": "world"})
	var out map[string]any
	if err := v.verify(jws, &out); err != nil || out["hello"] != "world" {
		t.Fatalf("valid JWS rejected: %v %v", out, err)
	}

	parts := strings.Split(jws, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"hello":"mallory"}`))
	if err := v.verify(strings.Join(parts, "."), &out); err == nil {
		t.Fatal("tampered payload accepted")
	}
	stranger := newPKI(t, oidAppStoreLeaf, oidAppleWWDRIntermediate)
	if err := v.verify(stranger.sign(t, map[string]any{}), &out); err == nil {
		t.Fatal("chain to an unknown root accepted")
	}
	unmarked := newPKI(t, nil, oidAppleWWDRIntermediate)
	if err := (verifier{roots: unmarked.roots, now: time.Now}).verify(unmarked.sign(t, map[string]any{}), &out); err == nil {
		t.Fatal("leaf without Apple's marker accepted")
	}
	if err := v.verify("not.a.jws", &out); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestEmbeddedRootIsApples(t *testing.T) {
	root, err := x509.ParseCertificate(appleRootG3)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(root.Raw)
	const want = "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("root fingerprint %s", got)
	}
}

type storeServer struct {
	*httptest.Server
	pub      *ecdsa.PublicKey
	status   int
	renewal  map[string]any
	expires  time.Time
	httpCode int
	sandbox  bool
}

func newStore(t *testing.T, p pki) (*Gateway, *storeServer) {
	t.Helper()
	keyPEM, key := p8(t)
	s := &storeServer{pub: &key.PublicKey, status: statusActive, renewal: map[string]any{"autoRenewStatus": 1}, expires: time.Now().Add(30 * 24 * time.Hour), httpCode: 200}
	handler := func(sandbox bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			claims := jwt.MapClaims{}
			parsed, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return s.pub, nil }, jwt.WithAudience("appstoreconnect-v1"))
			if err != nil || claims["iss"] != "issuer-1" || claims["bid"] != bundle || parsed.Header["kid"] != "STOREKEY1" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if s.sandbox != sandbox {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if s.httpCode != 200 {
				w.WriteHeader(s.httpCode)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"lastTransactions": []any{map[string]any{
				"originalTransactionId": "2000000001", "status": s.status,
				"signedTransactionInfo": p.sign(t, tx(s.expires)), "signedRenewalInfo": p.sign(t, s.renewal),
			}}}}})
		}
	}
	prod, sandbox := httptest.NewServer(handler(false)), httptest.NewServer(handler(true))
	t.Cleanup(prod.Close)
	t.Cleanup(sandbox.Close)
	s.Server = prod
	store, err := New(Config{BundleID: bundle, IssuerID: "issuer-1", KeyID: "STOREKEY1", Key: keyPEM, AppAppleID: 42,
		URL: prod.URL, SandboxURL: sandbox.URL}, p.roots)
	if err != nil {
		t.Fatal(err)
	}
	return store, s
}

func TestVerifyTransactionUsesTheAuthoritativeStatus(t *testing.T) {
	p := newPKI(t, oidAppStoreLeaf, oidAppleWWDRIntermediate)
	store, srv := newStore(t, p)
	ctx := context.Background()
	signed := p.sign(t, tx(time.Now().Add(time.Hour)))

	sub, err := store.VerifyTransaction(ctx, signed)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Provider != subscription.AppStore || sub.Status != subscription.StatusActive || !sub.AutoRenew || sub.ProviderRef != "2000000001" || sub.Account != account {
		t.Fatalf("sub = %+v", sub)
	}
	if !sub.CurrentPeriodEnd.Equal(srv.expires.Truncate(time.Millisecond).UTC()) {
		t.Fatalf("period end from the status API: %v vs %v", sub.CurrentPeriodEnd, srv.expires)
	}

	srv.renewal = map[string]any{"autoRenewStatus": 0}
	if sub, _ := store.VerifyTransaction(ctx, signed); sub.Status != subscription.StatusCanceled || sub.AutoRenew {
		t.Fatalf("auto-renew off must read as canceled: %+v", sub)
	}
	grace := time.Now().Add(6 * 24 * time.Hour)
	srv.status, srv.renewal = statusGracePeriod, map[string]any{"autoRenewStatus": 1, "gracePeriodExpiresDate": grace.UnixMilli()}
	if sub, _ := store.VerifyTransaction(ctx, signed); sub.Status != subscription.StatusInGrace || sub.CurrentPeriodEnd.UnixMilli() != grace.UnixMilli() {
		t.Fatalf("grace: %+v", sub)
	}
	srv.status = statusRevoked
	if sub, _ := store.VerifyTransaction(ctx, signed); sub.Status != subscription.StatusRevoked {
		t.Fatalf("revoked: %+v", sub)
	}

	srv.httpCode = http.StatusServiceUnavailable // Apple is down: the signed transaction decides
	if sub, err := store.VerifyTransaction(ctx, signed); err != nil || sub.Status != subscription.StatusActive {
		t.Fatalf("outage fallback: %+v %v", sub, err)
	}

	other := tx(time.Now().Add(time.Hour))
	other["bundleId"] = "com.example.other"
	if _, err := store.VerifyTransaction(ctx, p.sign(t, other)); !errors.Is(err, subscription.ErrUnverified) {
		t.Fatalf("foreign bundle accepted: %v", err)
	}
	consumable := tx(time.Now().Add(time.Hour))
	consumable["type"] = "Consumable"
	if _, err := store.VerifyTransaction(ctx, p.sign(t, consumable)); !errors.Is(err, subscription.ErrNotSubscription) {
		t.Fatalf("consumable accepted: %v", err)
	}
}

func TestSubscriptionFallsBackToSandbox(t *testing.T) {
	p := newPKI(t, oidAppStoreLeaf, oidAppleWWDRIntermediate)
	store, srv := newStore(t, p)
	srv.sandbox = true // e.g. an App Review purchase
	sub, err := store.Subscription(context.Background(), "2000000001")
	if err != nil || sub.Status != subscription.StatusActive {
		t.Fatalf("sandbox fallback: %+v %v", sub, err)
	}
	if _, err := store.Subscription(context.Background(), "unknown"); !errors.Is(err, subscription.ErrNotFound) {
		t.Fatalf("unknown subscription: %v", err)
	}
}

func TestParseNotification(t *testing.T) {
	p := newPKI(t, oidAppStoreLeaf, oidAppleWWDRIntermediate)
	store, _ := newStore(t, p)
	ctx := context.Background()
	payload := map[string]any{
		"notificationType": "EXPIRED", "notificationUUID": "uuid-1", "signedDate": time.Now().UnixMilli(),
		"data": map[string]any{
			"bundleId": bundle, "appAppleId": 42, "environment": "Production", "status": statusExpired,
			"signedTransactionInfo": p.sign(t, tx(time.Now().Add(-time.Hour))), "signedRenewalInfo": p.sign(t, map[string]any{"autoRenewStatus": 0}),
		},
	}
	id, sub, err := store.ParseNotification(ctx, p.sign(t, payload))
	if err != nil || id != "uuid-1" || sub.Status != subscription.StatusExpired || sub.ProviderRef != "2000000001" {
		t.Fatalf("id=%s sub=%+v err=%v", id, sub, err)
	}

	payload["data"].(map[string]any)["appAppleId"] = 7
	if _, _, err := store.ParseNotification(ctx, p.sign(t, payload)); !errors.Is(err, subscription.ErrInvalidNotification) {
		t.Fatalf("notification for another app accepted: %v", err)
	}
	stranger := newPKI(t, oidAppStoreLeaf, oidAppleWWDRIntermediate)
	if _, _, err := store.ParseNotification(ctx, stranger.sign(t, payload)); !errors.Is(err, subscription.ErrInvalidNotification) {
		t.Fatalf("notification signed by a stranger accepted: %v", err)
	}
	test := map[string]any{"notificationType": "TEST", "notificationUUID": "uuid-2", "data": map[string]any{"bundleId": bundle, "environment": "Sandbox"}}
	if id, sub, err := store.ParseNotification(ctx, p.sign(t, test)); err != nil || id != "uuid-2" || sub.ProviderRef != "" {
		t.Fatalf("test notification: %s %+v %v", id, sub, err)
	}
}
