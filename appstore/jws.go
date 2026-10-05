package appstore

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"
)

// Apple marks the certificates allowed to sign App Store data with these extensions.
var (
	oidAppStoreLeaf          = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 11, 1}
	oidAppleWWDRIntermediate = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 1}
)

// verifier checks App Store JWS signatures: an ES256 signature by a leaf certificate that chains
// to Apple's root through Apple's intermediate, as described in Apple's App Store Server Library.
type verifier struct {
	roots *x509.CertPool
	now   func() time.Time
}

var errInvalidSignature = errors.New("appstore: invalid App Store signature")

// verify checks a JWS and decodes its payload into out.
func (v verifier) verify(jws string, out any) error {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return errInvalidSignature
	}
	rawHeader, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	payload, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	signature, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || len(signature) != 64 {
		return errInvalidSignature
	}
	var header struct {
		Alg string   `json:"alg"`
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil || header.Alg != "ES256" || len(header.X5C) < 2 {
		return errInvalidSignature
	}
	certs := make([]*x509.Certificate, len(header.X5C))
	for i, enc := range header.X5C {
		der, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			return errInvalidSignature
		}
		if certs[i], err = x509.ParseCertificate(der); err != nil {
			return errInvalidSignature
		}
	}
	leaf, intermediate := certs[0], certs[1]
	if !hasExtension(leaf, oidAppStoreLeaf) || !hasExtension(intermediate, oidAppleWWDRIntermediate) {
		return fmt.Errorf("%w: certificates lack Apple's markers", errInvalidSignature)
	}
	// Validity is checked at signing time so that genuine but older payloads stay verifiable.
	var dated struct {
		SignedDate int64 `json:"signedDate"`
	}
	_ = json.Unmarshal(payload, &dated)
	at := v.now()
	if dated.SignedDate > 0 {
		at = time.UnixMilli(dated.SignedDate)
	}
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: v.roots, Intermediates: intermediates, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("%w: %w", errInvalidSignature, err)
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errInvalidSignature
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return errInvalidSignature
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("appstore: decode signed payload: %w", err)
	}
	return nil
}

func hasExtension(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	return slices.ContainsFunc(c.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(oid) })
}
