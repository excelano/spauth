# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub Security Advisories at https://github.com/excelano/spauth/security/advisories/new. If you would rather not use GitHub, email david.anderson@excelano.com instead. I aim to respond within seven days.

Please do not open public issues for security problems.

## Supported versions

The latest release receives security fixes. Older versions are not supported.

## What spauth can access

spauth is a library, not a service. On behalf of the program that imports it, it talks over HTTPS to `login.microsoftonline.com` for device-code sign-in and token refresh, to `graph.microsoft.com` for whatever Graph requests the importing program makes, and to the addresses Graph hands back for moving file content, which are on the tenant's own SharePoint Online host: the redirect a download follows and the upload URL of a large-file upload session. It requests one delegated permission, `Sites.ReadWrite.All`, under the "Excelano SharePoint tools" app registration, and acts only as the signed-in user. It runs no subprocesses and makes no network call to any other address.

## What spauth stores

A refresh token, in MSAL's cache format, at the path the importing program names; for the Excelano tools that is `~/.config/excelano/sp-token.json`. On Windows the contents are encrypted with DPAPI, under a key Windows derives from the user's logon credentials, so a copy of the file taken off that account, in a backup, a synced folder or a disk image, cannot be read. On Linux and macOS the file is plaintext and its only protection is the file mode, 0600 in a 0700 directory, which keeps other accounts on the host out and does nothing for a copy. On every platform, any program running as the same user can read the token. Delete the file to force re-authentication; revoke the granted permission at https://myaccount.microsoft.com/applications to invalidate the token server-side. There is no telemetry, no analytics, and no remote logging.
