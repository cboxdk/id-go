// Command publish-manifest declares this app's authorization roles and permissions
// in code and pushes them to Cbox ID — the Go counterpart of Laravel's
// `php artisan cbox-id:publish-manifest`. Run it on deploy so the Cbox ID console
// always reflects the app's current catalog; republishing an unchanged manifest is a
// no-op. The app's client must hold the apps.manifest scope.
//
//	CBOX_ID_ISSUER=https://id.acme.com \
//	CBOX_ID_CLIENT_ID=cid_... \
//	CBOX_ID_CLIENT_SECRET=csec_... \
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
		// No RedirectURI: publishing is a client-credentials call, not a sign-in.

		// Declare the app's authorization catalog in code. Cbox ID owns identity and
		// who holds what; the app owns what each role means.
		Permissions: []cboxid.Permission{
			{Key: "invoices:create", Description: "Create invoices"},
			// TenantAssignable: an organization's own admins may grant this one in a
			// custom role. Permissions are not self-serve unless they say so.
			{Key: "invoices:read", Description: "View invoices", TenantAssignable: true},
			{Key: "support:impersonate", Description: "Act as a customer"},
		},
		Roles: []cboxid.Role{
			{
				Key:         "billing-admin",
				Name:        "Billing Admin",
				Description: "Full billing access",
				Permissions: []string{"invoices:create", "invoices:read"},
			},
			{
				// StaffOnly: assignable by your own staff only, never offered to an
				// organization's admins. Roles are tenant-assignable unless they say so.
				Key:         "support",
				Name:        "Support",
				Description: "Vendor support staff",
				Permissions: []string{"support:impersonate", "invoices:read"},
				StaffOnly:   true,
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
