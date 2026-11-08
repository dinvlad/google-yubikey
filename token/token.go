package token

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/dinvlad/google-yubikey/v2/yubikey"
	"github.com/go-piv/piv-go/v2/piv"
)

type Type string

const (
	IDToken     Type = "id"
	AccessToken Type = "access"

	DefaultScope = "https://www.googleapis.com/auth/cloud-platform"
)

type Minter struct {
	email  *mail.Address
	yk     *piv.YubiKey
	signer crypto.Signer
	params chan tokenParams
}

type tokenParams struct {
	typ      Type
	audience string
	scopes   []string
	result   chan tokenResult
}

type tokenResult struct {
	token string
	err   error
}

func NewMinter(serial uint, slot piv.Slot, email *mail.Address) (m *Minter, err error) {
	m = &Minter{
		email:  email,
		params: make(chan tokenParams),
	}
	m.yk, err = yubikey.Open(serial)
	if err != nil {
		return
	}
	if m.signer, err = signer(m.yk, slot); err != nil {
		return
	}
	go m.worker()
	return
}

func (m *Minter) Close() {
	if m.yk != nil {
		m.yk.Close()
	}
	close(m.params)
}

func (m *Minter) worker() {
	for p := range m.params {
		token, err := m.mint(p.typ, p.audience, p.scopes)
		p.result <- tokenResult{token, err}
		close(p.result)
	}
}

func (m *Minter) Generate(typ Type, audience string, scopes []string) (string, error) {
	results := make(chan tokenResult)
	m.params <- tokenParams{typ, audience, scopes, results}
	r := <-results
	return r.token, r.err
}

func (m *Minter) mint(typ Type, audience string, scopes []string) (string, error) {
	jwt, err := signJWT(m.signer, m.email.Address, audience, scopes)
	if err != nil {
		return "", err
	}
	if typ == IDToken {
		return jwt, nil
	}
	return accessToken(jwt)
}

func ValidateTokenParams(typ Type, audience string, scopes []string) (_ string, _ []string, err error) {
	switch typ {
	case AccessToken:
		if audience != "" {
			err = errors.New("custom audience is not supported for access tokens")
			return
		} else if len(scopes) == 0 {
			scopes = []string{DefaultScope}
		}
		audience = "https://oauth2.googleapis.com/token"
	case IDToken:
		if audience == "" {
			err = errors.New("audience is required for ID tokens")
			return
		} else if len(scopes) > 0 {
			err = errors.New("scopes are not supported for ID tokens")
			return
		}
	default:
		err = fmt.Errorf(`unknown token type %q: must be "%s" or "%s"`, typ, AccessToken, IDToken)
	}
	return audience, scopes, err
}

// signer reads the slot's certificate and policies and returns a signer for its key.
func signer(yk *piv.YubiKey, slot piv.Slot) (crypto.Signer, error) {
	cert, err := yk.Certificate(slot)
	if err != nil {
		return nil, fmt.Errorf("reading certificate: %w", err)
	}

	info, err := yk.KeyInfo(slot)
	if err != nil {
		return nil, fmt.Errorf("reading key info: %w", err)
	}

	return yubikey.PrivateKey(yk, slot, cert.PublicKey, info.PINPolicy, info.TouchPolicy)
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
