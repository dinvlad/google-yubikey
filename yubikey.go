package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

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
