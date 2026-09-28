module github.com/excelano/spauth

go 1.26.0

// A bump to MSAL reaches six shipped binaries, across xql and xfiles, on their
// next release. Read the MSAL changelog before taking a minor.
require (
	github.com/AzureAD/microsoft-authentication-library-for-go v1.10.0
	github.com/excelano/atrest v0.1.1
	golang.org/x/term v0.46.0
)

require (
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
