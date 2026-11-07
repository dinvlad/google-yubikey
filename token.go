package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
)

type tokenType string

const (
	IDToken     tokenType = "id"
	AccessToken tokenType = "access"
)

// generateToken creates an access or ID token for the service account.
func generateToken(serial uint, account string, typ tokenType, audience string, scopes []string) (string, error) {
	switch typ {
	case AccessToken:
		if audience != "" {
			return "", errors.New("custom audience is not supported for access tokens")
		} else if len(scopes) == 0 {
			scopes = []string{"https://www.googleapis.com/auth/cloud-platform"}
		}
		audience = "https://oauth2.googleapis.com/token"
	case IDToken:
		if audience == "" {
			return "", errors.New("audience is required for ID tokens")
		} else if len(scopes) > 0 {
			return "", errors.New("scopes are not supported for ID tokens")
		}
	default:
		return "", fmt.Errorf(`unknown token type %q: must be "%s" or "%s"`, typ, AccessToken, IDToken)
	}

	yk, err := open(serial)
	if err != nil {
		return "", err
	}
	defer yk.Close()

	sign, err := signer(yk)
	if err != nil {
		return "", err
	}

	jwt, err := signJWT(sign, account, audience, scopes)
	if err != nil {
		return "", err
	}
	if typ == IDToken {
		return jwt, nil
	}
	return accessToken(jwt)
}

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

// signJWT returns a signed RS256 JWT for the given issuer, audience and scopes.
func signJWT(sign crypto.Signer, iss, aud string, scopes []string) (string, error) {
	now := time.Now().Unix()

	header, err := json.Marshal(jwtHeader{"JWT", "RS256"})
	if err != nil {
		return "", err
	}

	c := jwtClaims{iss, aud, now, now + 3600, strings.Join(scopes, " ")}
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

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// accessToken exchanges a signed JWT assertion for an OAuth2 access token.
func accessToken(assertion string) (string, error) {
	resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var res tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("token exchange: %s", resp.Status)
		}
		return "", err
	}
	if resp.StatusCode != http.StatusOK || res.Error != "" {
		msg := res.ErrorDescription
		if msg == "" {
			msg = res.Error
		}
		if msg == "" {
			msg = resp.Status
		}
		return "", fmt.Errorf("token exchange: %s", msg)
	}
	return res.AccessToken, nil
}
