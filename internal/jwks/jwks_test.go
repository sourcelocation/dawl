package jwks

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestECKeysVerifyAndInvalidPointsAreIgnored(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, err := key.PublicKey.Bytes() // 0x04 ‖ X ‖ Y
	if err != nil {
		t.Fatal(err)
	}
	x, y := point[1:33], point[33:]
	offCurve := bytes.Clone(y)
	offCurve[31] ^= 1

	b64 := base64.RawURLEncoding.EncodeToString
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{
			map[string]any{"kid": "good", "kty": "EC", "crv": "P-256", "x": b64(x), "y": b64(y)},
			map[string]any{"kid": "off-curve", "kty": "EC", "crv": "P-256", "x": b64(x), "y": b64(offCurve)},
			map[string]any{"kid": "short", "kty": "EC", "crv": "P-256", "x": b64(x[1:]), "y": b64(y)},
		}})
	}))
	defer srv.Close()
	set := New(srv.URL, srv.Client())

	for kid, valid := range map[string]bool{"good": true, "off-curve": false, "short": false} {
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": "s"})
		tok.Header["kid"] = kid
		signed, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = jwt.Parse(signed, set.Keyfunc(t.Context()), jwt.WithValidMethods([]string{"ES256"}))
		if (err == nil) != valid {
			t.Errorf("%s: err = %v, want valid = %v", kid, err, valid)
		}
	}
}
