// Command cli is a minimal example of logging a CLI in to Cbox ID using the device
// authorization grant (RFC 8628) — the same flow the GitHub CLI uses: the tool
// prints a short code, the user approves it in a browser on any device, and the CLI
// receives the tokens.
//
// Run it with the instance and client configured in the environment:
//
//	CBOX_ID_ISSUER=https://id.acme.com \
//	CBOX_ID_CLIENT_ID=client_... \
//	go run ./examples/cli
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	cboxid "github.com/cboxdk/id-go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	client, err := cboxid.New(ctx, cboxid.Config{
		Issuer:      os.Getenv("CBOX_ID_ISSUER"),
		ClientID:    os.Getenv("CBOX_ID_CLIENT_ID"),
		RedirectURI: "http://localhost", // unused by the device flow, but required
		Scopes:      []string{"openid", "profile", "email", "offline_access"},
	})
	if err != nil {
		return err
	}

	auth, err := client.RequestDeviceAuthorization(ctx, cboxid.DeviceParams{})
	if err != nil {
		return err
	}

	fmt.Printf("\n  To sign in, visit:  %s\n", auth.VerificationURI)
	fmt.Printf("  And enter the code: %s\n\n", auth.UserCode)
	if auth.VerificationURIComplete != "" {
		fmt.Printf("  Or open directly:   %s\n\n", auth.VerificationURIComplete)
	}
	fmt.Println("  Waiting for approval…")

	// Bound the wait by the code's lifetime.
	pollCtx, cancel := context.WithDeadline(ctx, auth.Expiry.Add(time.Second))
	defer cancel()

	user, err := client.PollDeviceToken(pollCtx, auth)
	if err != nil {
		return err
	}

	fmt.Printf("\n  Signed in as %s <%s>.\n", user.Name, user.Email)
	// Persist user.Token (it holds the refresh token) to your CLI's config file so
	// the next run can reuse it instead of prompting again.
	return nil
}
