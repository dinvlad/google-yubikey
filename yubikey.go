package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/term"
)

func generateKey(serial uint, subject string, validDays int) error {
	yk, err := open(serial)
	if err != nil {
		return err
	}
	defer yk.Close()

	mgmt, err := promptManagementKey()
	if err != nil {
		return err
	}

	if subject == "" {
		s, err := yk.Serial()
		if err != nil {
			return err
		}
		subject = fmt.Sprintf("yk-%d", s)
	}

	pub, err := yk.GenerateKey(mgmt, slot, piv.Key{
		Algorithm:   piv.AlgorithmRSA2048,
		PINPolicy:   pinPolicy,
		TouchPolicy: touchPolicy,
	})
	if err != nil {
		return err
	}

	priv, err := yk.PrivateKey(slot, pub, piv.KeyAuth{
		PINPolicy: pinPolicy,
		PINPrompt: promptPIN,
	})
	if err != nil {
		return err
	}
	sign, ok := priv.(crypto.Signer)
	if !ok {
		return errors.New("key does not implement crypto.Signer")
	}

	cert, err := generateCert(subject, validDays, pub, sign)
	if err != nil {
		return err
	}
	if touchPolicy != piv.TouchPolicyNever {
		fmt.Fprintln(os.Stderr, "Touch your YubiKey...")
	}
	if err := yk.SetCertificate(mgmt, slot, cert); err != nil {
		return err
	}
	return pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

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
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("management key must be 16, 24 or 32 bytes, got %d", len(key))
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
