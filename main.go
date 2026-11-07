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

const usage = "usage: google-yubikey <generate-key|token|serve> [flags]"

var (
	slot        = piv.SlotAuthentication
	pinPolicy   piv.PINPolicy
	touchPolicy piv.TouchPolicy
	scopes      []string
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.Uint("serial", 0, "YubiKey serial (0 for first available)")
	fs.Func("slot", "authentication|signature|key-management|card-authentication (default: authentication)", parseSlot)

	switch cmd {
	case "generate-key":
		fs.String("subject", "yk-<serial>", "subject CN")
		fs.Int("valid-days", 365, "valid days")
		fs.String("algorithm", "rsa2048", "rsa2048|rsa4096")
		fs.Func("pin-policy", "never|once|always|match-once|match-always", parsePinPolicy)
		fs.Func("touch-policy", "never|always|cached", parseTouchPolicy)
	case "token":
		fs.String("account", "", "Service Account email")
		fs.String("token-type", "access", "access|id")
		fs.String("audience", "", "ID token audience")
		fs.Func("scopes", "https://www.googleapis.com/auth/cloud-platform[,...]", parseScopes)
	case "serve":
		fs.String("account", "", "Service Account email")
		fs.Int64("numeric-project-id", 0, "numeric project id")
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
	fmt.Fprintf(os.Stderr, "%s: not implemented\n", cmd)
	os.Exit(1)
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
	scopes = strings.Split(s, ",")
	if len(scopes) == 0 {
		scopes = []string{"https://www.googleapis.com/auth/cloud-platform"}
	}
	return nil
}
