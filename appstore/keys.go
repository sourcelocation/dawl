package appstore

import (
	"crypto/ecdsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

//go:embed AppleRootCA-G3.cer
var appleRootG3 []byte

// Roots returns the trust anchor for App Store signatures: Apple Root CA - G3
// (SHA-256 63:34:3A:BF:B8:9A:6A:03:EB:B5:7E:9B:3F:5F:A7:BE:7C:4F:5C:75:6F:30:17:B3:A8:C4:88:C3:65:3E:91:79).
func Roots() *x509.CertPool {
	root, err := x509.ParseCertificate(appleRootG3)
	if err != nil {
		panic("appstore: embedded root certificate is corrupt: " + err.Error())
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return pool
}

// parseP8 reads an Apple .p8 private key (PKCS #8, P-256).
func parseP8(p8 string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(p8)))
	if block == nil {
		return nil, errors.New("appstore: key is not PEM encoded")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("appstore: parse key: %w", err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("appstore: key is not an ECDSA key")
	}
	return ec, nil
}

// signer issues the short-lived ES256 JWTs the App Store Server API authenticates with, reusing
// each token until shortly before it expires. Callers serialise access.
type signer struct {
	key    *ecdsa.PrivateKey
	keyID  string
	claims jwt.MapClaims
	ttl    time.Duration

	token   string
	expires time.Time
}

func (s *signer) sign(now time.Time) (string, error) {
	if s.token != "" && now.Before(s.expires.Add(-time.Minute)) {
		return s.token, nil
	}
	claims := jwt.MapClaims{"iat": now.Unix(), "exp": now.Add(s.ttl).Unix()}
	maps.Copy(claims, s.claims)
	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["kid"] = s.keyID
	token, err := t.SignedString(s.key)
	if err != nil {
		return "", err
	}
	s.token, s.expires = token, now.Add(s.ttl)
	return token, nil
}
