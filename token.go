package main

import (
	"crypto"
	"fmt"

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
