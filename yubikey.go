package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/term"
)

// open returns the YubiKey with the given serial,
// or the first one when serial is 0.
func open(serial uint) (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	for _, card := range cards {
		yk, err := piv.Open(card)
		if err != nil {
			continue
		}
		s, err := yk.Serial()
		if err == nil && (serial == 0 || uint(s) == serial) {
			return yk, nil
		}
		yk.Close()
	}
	if serial != 0 {
		return nil, fmt.Errorf("YubiKey %d not found", serial)
	}
	return nil, errors.New("no YubiKey found")
}

// promptManagementKey reads a hex-encoded 24-byte management key without echo.
func promptManagementKey() ([]byte, error) {
	fmt.Fprint(os.Stderr, "Enter a management key [blank to use default key]: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}

	s := strings.TrimSpace(string(b))
	if s == "" {
		return piv.DefaultManagementKey, nil
	}
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("management key must be hex: %w", err)
	}
	if len(key) != 24 {
		return nil, fmt.Errorf("management key must be 24 bytes, got %d", len(key))
	}
	return key, nil
}

// promptPIN reads the PIV PIN without echo.
func promptPIN() (string, error) {
	fmt.Fprint(os.Stderr, "Enter PIN: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// generateCert builds and signs a self-signed certificate.
func generateCert(subject string, validDays int, pub crypto.PublicKey, sign crypto.Signer) (*x509.Certificate, error) {
	now := time.Now()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.AddDate(0, 0, validDays),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, sign)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}
