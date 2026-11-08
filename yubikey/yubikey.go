package yubikey

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

// GenerateKey creates a new key and self-signed certificate on the YubiKey
// replacing any existing key, and prints the certificate as PEM.
func GenerateKey(
	serial uint, slot piv.Slot, subject string,
	validDays int, pp piv.PINPolicy, tp piv.TouchPolicy,
) error {
	yk, err := Open(serial)
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
		PINPolicy:   pp,
		TouchPolicy: tp,
	})
	if err != nil {
		return err
	}

	sign, err := PrivateKey(yk, slot, pub, pp, tp)
	if err != nil {
		return err
	}

	cert, err := generateCert(subject, validDays, pub, sign)
	if err != nil {
		return err
	}
	if err := yk.SetCertificate(mgmt, slot, cert); err != nil {
		return err
	}
	return pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// Open returns the YubiKey with the given serial,
// or the first one when serial is 0.
func Open(serial uint) (*piv.YubiKey, error) {
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

// pinPrompt reads the PIV PIN without echo.
func pinPrompt(tp piv.TouchPolicy) func() (string, error) {
	return func() (string, error) {
		fmt.Fprint(os.Stderr, "Enter PIN: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if tp != piv.TouchPolicyNever {
			fmt.Fprintln(os.Stderr, "Touch your YubiKey...")
		}
		return strings.TrimSpace(string(b)), nil
	}
}

// PrivateKey returns a signer for the private key, prompting for the PIN when needed.
func PrivateKey(yk *piv.YubiKey, slot piv.Slot, pub crypto.PublicKey, pp piv.PINPolicy, tp piv.TouchPolicy) (crypto.Signer, error) {
	priv, err := yk.PrivateKey(slot, pub, piv.KeyAuth{
		PINPolicy: pp,
		PINPrompt: pinPrompt(tp),
	})
	if err != nil {
		return nil, err
	}
	sign, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("key does not implement crypto.Signer")
	}
	return sign, nil
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
