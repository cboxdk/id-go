// Command publish-manifest declares this app's authorization roles and permissions
// in code and pushes them to Cbox ID — the Go counterpart of Laravel's
// `php artisan cbox-id:publish-manifest`. Run it on deploy so the Cbox ID console
// always reflects the app's current catalog; republishing an unchanged manifest is a
// no-op. The app's client must hold the apps.manifest scope.
//
//	CBOX_ID_ISSUER=https://id.acme.com \
//	CBOX_ID_CLIENT_ID=client_... \
//	CBOX_ID_CLIENT_SECRET=secret_... \
//	go run ./examples/publish-manifest
package main

import (
	"context"
	"fmt"
	"os"

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
		Issuer:       os.Getenv("CBOX_ID_ISSUER"),
		ClientID:     os.Getenv("CBOX_ID_CLIENT_ID"),
		ClientSecret: os.Getenv("CBOX_ID_CLIENT_SECRET"),
		RedirectURI:  "http://localhost", // unused when only publishing, but required

		// Declare the app's authorization catalog in code. Cbox ID owns identity and
		// who holds what; the app owns what each role means.
		Permissions: []cboxid.Permission{
			{Key: "invoices:create", Description: "Create invoices"},
			{Key: "invoices:read", Description: "View invoices"},
		},
		Roles: []cboxid.Role{
			{
				Key:         "billing-admin",
				Name:        "Billing Admin",
				Description: "Full billing access",
				Permissions: []string{"invoices:create", "invoices:read"},
			},
		},
	})
	if err != nil {
		return err
	}

	summary, err := client.PublishManifest(ctx)
	if err != nil {
		return err
	}

	if summary.Unchanged {
		fmt.Println("Manifest already up to date.")
		return nil
	}
	fmt.Printf("Manifest published — %d role(s), %d permission(s).\n",
		summary.RolesDeclared, summary.PermissionsDeclared)
	if len(summary.OrphanedRoles) > 0 || len(summary.OrphanedPermissions) > 0 {
		fmt.Printf("Flagged as orphaned — roles: %v, permissions: %v\n",
			summary.OrphanedRoles, summary.OrphanedPermissions)
	}
	return nil
}
