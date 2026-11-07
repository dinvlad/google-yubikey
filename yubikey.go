package main

import (
	"errors"
	"fmt"

	"github.com/go-piv/piv-go/v2/piv"
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
