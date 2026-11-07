// Command google-yubikey generates Google Service Account tokens with a YubiKey.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
)

const (
	usage = "usage: google-yubikey <generate-key|token|serve> [flags]"
)

var (
	slot        = piv.SlotAuthentication
	pinPolicy   = piv.PINPolicyOnce
	touchPolicy = piv.TouchPolicyNever

	serial    *uint
	subject   *string
	validDays *int
	account   *string
	tokType   *string
	audience  *string
	scopes    []string
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)

	fs.Func("slot", `authentication|signature|key-management|card-authentication (default "authentication")`, parseSlot)
	serial = fs.Uint("serial", 0, "YubiKey serial (0 for first available)")

	switch cmd {
	case "generate-key":
		subject = fs.String("subject", "", `subject Common Name (default "yk-<serial>")`)
		validDays = fs.Int("valid-days", 365, "valid days")
		fs.Func("pin-policy", `never|once|always|match-once|match-always (default "once")`, parsePinPolicy)
		fs.Func("touch-policy", `never|always|cached (default "never")`, parseTouchPolicy)
	case "token":
		account = fs.String("account", "", "Service Account email (required)")
		tokType = fs.String("type", "access", "access|id")
		audience = fs.String("audience", "", "ID token audience")
		fs.Func("scopes", "comma-separated Google OAuth 2.0 scopes for access token "+
			`(default: "https://www.googleapis.com/auth/cloud-platform")`, parseScopes)
	case "serve":
		account = fs.String("account", "", "Service Account email (required)")
		fs.Uint64("numeric-project-id", 0, "numeric project id")
		fs.Int("cache-lifetime", 10, "cache lifetime")
		fs.String("addr", "127.0.0.1:1692", "listen address")
	case "-h", "--help":
		fmt.Println(usage)
		return
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	fs.Parse(args)

	t := tokenType(*tokType)
	if err := validateAccount(t); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var err error
	switch cmd {
	case "generate-key":
		err = generateKey(*serial, *subject, *validDays)
	case "token":
		var tok string
		if tok, err = generateToken(*serial, *account, t, *audience, scopes, 3600); err == nil {
			fmt.Println(tok)
		}
	case "serve":
		err = fmt.Errorf("%s: not implemented", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseSlot(s string) error {
	switch s {
	case "authentication":
		slot = piv.SlotAuthentication
	case "signature":
		slot = piv.SlotSignature
	case "key-management":
		slot = piv.SlotKeyManagement
	case "card-authentication":
		slot = piv.SlotCardAuthentication
	default:
		return errors.New(`must be one of "authentication", "signature", "key-management" or "card-authentication"`)
	}
	return nil
}

func parsePinPolicy(s string) error {
	switch s {
	case "never":
		pinPolicy = piv.PINPolicyNever
	case "once":
		pinPolicy = piv.PINPolicyOnce
	case "always":
		pinPolicy = piv.PINPolicyAlways
	case "match-once":
		pinPolicy = piv.PINPolicyMatchOnce
	case "match-always":
		pinPolicy = piv.PINPolicyMatchAlways
	default:
		return errors.New(`must be one of "never", "once", "always", "match-once" or "match-always"`)
	}
	return nil
}

func parseTouchPolicy(s string) error {
	switch s {
	case "never":
		touchPolicy = piv.TouchPolicyNever
	case "always":
		touchPolicy = piv.TouchPolicyAlways
	case "cached":
		touchPolicy = piv.TouchPolicyCached
	default:
		return errors.New(`must be one of "never", "always" or "cached"`)
	}
	return nil
}

func parseScopes(s string) error {
	scopes = nil
	for v := range strings.SplitSeq(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			scopes = append(scopes, v)
		}
	}
	return nil
}

func validateAccount(typ tokenType) error {
	if typ != IDToken && typ != AccessToken {
		return nil
	}
	if *account == "" {
		return errors.New("Error: Service Account email is required")
	}
	return nil
}
