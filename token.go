package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
)

// signer reads the slot's certificate and policies and returns a signer for its key.
func signer(yk *piv.YubiKey) (crypto.Signer, error) {
	cert, err := yk.Certificate(slot)
	if err != nil {
		return nil, fmt.Errorf("reading certificate: %w", err)
	}

	info, err := yk.KeyInfo(slot)
	if err != nil {
		return nil, fmt.Errorf("reading key info: %w", err)
	}
	touchPolicy = info.TouchPolicy

	return privateKey(yk, cert.PublicKey, info.PINPolicy)
}

type jwtHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

type jwtClaims struct {
	Iss   string `json:"iss"`
	Aud   string `json:"aud"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
	Scope string `json:"scope,omitempty"`
}

// assertion returns a signed RS256 JWT for the given audience and scopes.
func assertion(sign crypto.Signer, iss, aud string, scopes []string, lifetime int) (string, error) {
	now := time.Now().Unix()

	header, err := json.Marshal(jwtHeader{"JWT", "RS256"})
	if err != nil {
		return "", err
	}

	c := jwtClaims{iss, aud, now, now + int64(lifetime), strings.Join(scopes, " ")}
	claims, err := json.Marshal(c)
	if err != nil {
		return "", err
	}

	b64 := base64.RawURLEncoding
	msg := b64.EncodeToString(header) + "." + b64.EncodeToString(claims)

	digest := sha256.Sum256([]byte(msg))
	sig, err := sign.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}

	return msg + "." + b64.EncodeToString(sig), nil
}
