// Package jwks resolves JWT verification keys from a provider's published JSON Web Key Set
// (Google's OIDC tokens on Play notifications). Keys are cached and refreshed when a token names
// a key the cache does not know — that is how providers rotate keys.
package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Set is a cached key set.
type Set struct {
	url  string
	http *http.Client

	mu      sync.Mutex
	keys    map[string]any
	fetched time.Time
}

// New builds a key set for the given JWKS URL.
func New(url string, client *http.Client) *Set {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Set{url: url, http: client, keys: map[string]any{}}
}

const (
	maxAge       = 6 * time.Hour
	refreshFloor = time.Minute // never hammer the provider, even under attack with random kids
)

// Keyfunc returns a jwt.Keyfunc resolving keys by the token's `kid`.
func (s *Set) Keyfunc(ctx context.Context) jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("jwks: token has no kid")
		}
		return s.key(ctx, kid)
	}
}

func (s *Set) key(ctx context.Context, kid string) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, ok := s.keys[kid]; ok && time.Since(s.fetched) < maxAge {
		return k, nil
	}
	if time.Since(s.fetched) >= refreshFloor {
		if err := s.refresh(ctx); err != nil {
			if k, ok := s.keys[kid]; ok { // provider unreachable: a known key is still good
				return k, nil
			}
			return nil, err
		}
	}
	if k, ok := s.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("jwks: unknown key %q", kid)
}

type document struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"keys"`
}

// refresh downloads the set (caller holds mu).
func (s *Set) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	res, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: fetch %s: %w", s.url, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: fetch %s: status %d", s.url, res.StatusCode)
	}
	var doc document
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&doc); err != nil {
		return fmt.Errorf("jwks: decode %s: %w", s.url, err)
	}
	keys := map[string]any{}
	for _, k := range doc.Keys {
		switch k.Kty {
		case "RSA":
			n, err1 := base64.RawURLEncoding.DecodeString(k.N)
			e, err2 := base64.RawURLEncoding.DecodeString(k.E)
			if err1 != nil || err2 != nil || len(e) > 4 {
				continue
			}
			keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		case "EC":
			if k.Crv != "P-256" {
				continue
			}
			x, err1 := base64.RawURLEncoding.DecodeString(k.X)
			y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			keys[k.Kid] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		}
	}
	s.keys, s.fetched = keys, time.Now()
	return nil
}
