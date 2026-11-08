// Command google-yubikey generates Google Service Account tokens with a YubiKey.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net/mail"
	"os"
	"strings"

	"github.com/dinvlad/google-yubikey/v2/metadata"
	"github.com/dinvlad/google-yubikey/v2/token"
	"github.com/dinvlad/google-yubikey/v2/yubikey"
	"github.com/go-piv/piv-go/v2/piv"
)

var (
	slot        = piv.SlotAuthentication
	pinPolicy   = piv.PINPolicyOnce
	touchPolicy = piv.TouchPolicyNever

	serial    *uint
	subject   *string
	validDays *int

	account  *string
	email    *mail.Address
	tokType  *string
	audience *string
	scopes   []string

	projectNum *uint64
	addr       *string
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: google-yubikey <generate-key|token|serve> [flags]")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.Usage = func() {
		usage()
		fs.PrintDefaults()
	}

	switch cmd {
	case "generate-key":
		subject = fs.String("subject", "", `subject Common Name (default "yk-<serial>")`)
		validDays = fs.Int("valid-days", 365, "valid days")
		fs.Func("pin-policy", `never|once|always|match-once|match-always (default "once")`, parsePinPolicy)
		fs.Func("touch-policy", `never|always|cached (default "never")`, parseTouchPolicy)
	case "token":
		parseAccount(fs)
		tokType = fs.String("type", "access", "access|id")
		audience = fs.String("audience", "", "ID token audience")
		parseScopes(fs)
	case "serve":
		parseAccount(fs)
		projectNum = fs.Uint64("project-number", 0, "Google project number")
		addr = fs.String("addr", "127.0.0.1:1692", "listen address")
		parseScopes(fs)
	case "-h", "-help", "--help":
		fs.Usage()
		return
	default:
		fs.Usage()
		os.Exit(2)
	}
	serial = fs.Uint("serial", 0, "YubiKey serial (0 for first available)")
	fs.Func("slot", `authentication|signature|key-management|card-authentication (default "authentication")`, parseSlot)
	fs.Parse(args)

	var err error
	switch cmd {
	case "generate-key":
		err = yubikey.GenerateKey(*serial, slot, *subject, *validDays, pinPolicy, touchPolicy)
	case "token":
		if err = requireSAEmail(fs, *account); err != nil {
			break
		}
		typ := token.Type(*tokType)
		audience, scopes, e := token.ValidateTokenParams(typ, *audience, scopes)
		if e != nil {
			err = e
			break
		}

		var tok string
		var m *token.Minter
		m, err = token.NewMinter(*serial, slot, email)
		if err == nil {
			tok, err = m.Generate(typ, audience, scopes)
		}
		defer m.Close()
		if err == nil {
			fmt.Println(tok)
		}
	case "serve":
		if err = requireSAEmail(fs, *account); err != nil {
			break
		}
		err = metadata.Serve(*serial, slot, email, *projectNum, scopes, *addr)
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

func parseAccount(fs *flag.FlagSet) {
	account = fs.String("account", "", "Service Account email (required)")
}

func parseScopes(fs *flag.FlagSet) {
	fs.Func("scopes", "comma-separated Google OAuth 2.0 scopes for access tokens "+
		`(default: "https://www.googleapis.com/auth/cloud-platform")`, func(s string) error {
		scopes = nil
		for v := range strings.SplitSeq(s, ",") {
			if v = strings.TrimSpace(v); v != "" {
				scopes = append(scopes, v)
			}
		}
		return nil
	})
}

func requireSAEmail(fs *flag.FlagSet, account string) (err error) {
	email, err = mail.ParseAddress(account)
	if err != nil || !strings.HasSuffix(account, ".iam.gserviceaccount.com") {
		fs.Usage()
		return errors.New("Error: a valid Service Account email is required")
	}
	return nil
}
