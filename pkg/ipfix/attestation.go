// Post-quantum attestation of IPFIX messages.
//
// Exported IPFIX telemetry is used to reason about traffic and security, so its
// integrity and origin matter. These helpers sign the serialized bytes of an
// IPFIX message with ML-DSA (FIPS 204) and produce a self-contained attestation,
// so an archived or forwarded message can be shown to be genuine and unaltered,
// even against an adversary with a quantum computer.
//
// Integrity is always checked. Authenticity, that the attestation came from a
// specific exporter, holds when the verifier pins the signer public key.
//
// This tooling is contributed by Quantova (https://quantova.org).
package ipfix

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

// Issuer identifies the tooling that produced an attestation.
const Issuer = "Quantova"

// DefaultAlgorithm is the ML-DSA parameter set used when none is given.
const DefaultAlgorithm = "ML-DSA-65"

// SupportedAlgorithms lists the ML-DSA parameter sets this package accepts.
var SupportedAlgorithms = []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}

// Attestation is a post-quantum signature over an IPFIX message.
type Attestation struct {
	Version       int    `json:"version"`
	Issuer        string `json:"issuer"`
	Algorithm     string `json:"algorithm"`
	CreatedAt     int64  `json:"created_at"`
	MessageSHA256 string `json:"message_sha256"`
	PublicKey     string `json:"public_key"`
	Signature     string `json:"signature"`
}

func supportedScheme(algorithm string) (sign.Scheme, error) {
	for _, name := range SupportedAlgorithms {
		if name == algorithm {
			return schemes.ByName(algorithm), nil
		}
	}
	return nil, fmt.Errorf("unsupported attestation algorithm: %s", algorithm)
}

// GenerateKey creates an ML-DSA key pair for the given parameter set.
func GenerateKey(algorithm string) (sign.PublicKey, sign.PrivateKey, error) {
	scheme, err := supportedScheme(algorithm)
	if err != nil {
		return nil, nil, err
	}
	return scheme.GenerateKey()
}

// SignBytes signs arbitrary bytes and returns a self-contained attestation.
// If priv is nil a fresh ephemeral key is generated and only integrity is
// established; pass a stable key whose public part is published to also prove
// authenticity.
func SignBytes(data []byte, algorithm string, priv sign.PrivateKey) (*Attestation, error) {
	scheme, err := supportedScheme(algorithm)
	if err != nil {
		return nil, err
	}
	if priv == nil {
		if _, priv, err = scheme.GenerateKey(); err != nil {
			return nil, err
		}
	}

	signature := scheme.Sign(priv, data, nil)
	pub, ok := priv.Public().(sign.PublicKey)
	if !ok {
		return nil, fmt.Errorf("private key does not expose a signature public key")
	}
	publicKeyBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(data)
	return &Attestation{
		Version:       1,
		Issuer:        Issuer,
		Algorithm:     algorithm,
		CreatedAt:     time.Now().Unix(),
		MessageSHA256: hex.EncodeToString(sum[:]),
		PublicKey:     base64.StdEncoding.EncodeToString(publicKeyBytes),
		Signature:     base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// VerifyBytes verifies an attestation against the given bytes. When
// expectedPublicKey is non-nil the attestation public key must match it.
func VerifyBytes(data []byte, att *Attestation, expectedPublicKey []byte) (bool, error) {
	if att == nil {
		return false, fmt.Errorf("attestation is nil")
	}
	scheme, err := supportedScheme(att.Algorithm)
	if err != nil {
		return false, err
	}

	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != att.MessageSHA256 {
		return false, nil
	}

	publicKeyBytes, err := base64.StdEncoding.DecodeString(att.PublicKey)
	if err != nil {
		return false, err
	}
	signature, err := base64.StdEncoding.DecodeString(att.Signature)
	if err != nil {
		return false, err
	}
	if expectedPublicKey != nil && !bytes.Equal(publicKeyBytes, expectedPublicKey) {
		return false, nil
	}

	pub, err := scheme.UnmarshalBinaryPublicKey(publicKeyBytes)
	if err != nil {
		return false, err
	}
	return scheme.Verify(pub, data, signature, nil), nil
}

// JSON serializes the attestation to indented JSON.
func (a *Attestation) JSON() ([]byte, error) {
	return json.MarshalIndent(a, "", "  ")
}
