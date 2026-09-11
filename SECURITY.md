# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub Security Advisories at https://github.com/excelano/spauth/security/advisories/new. If you would rather not use GitHub, email david.anderson@excelano.com instead. I aim to respond within seven days.

Please do not open public issues for security problems.

## Supported versions

The latest release receives security fixes. Older versions are not supported.

## What spauth can access

spauth is a library, not a service. On behalf of the program that imports it, it talks to two hosts over HTTPS: `login.microsoftonline.com` for device-code sign-in and token refresh, and `graph.microsoft.com` for whatever Graph requests the importing program makes. It requests one delegated permission, `Sites.ReadWrite.All`, under the "Excelano SharePoint tools" app registration, and acts only as the signed-in user. It runs no subprocesses and does no network calls of its own beyond those two hosts.

## What spauth stores

A refresh token, in MSAL's cache format, at the path the importing program names — for the Excelano tools that is `~/.config/excelano/sp-token.json`. The file is written with mode 0600 in a 0700 directory, through a temp file and rename so a partial write never replaces a good cache. Delete the file to force re-authentication; revoke the granted permission at https://myaccount.microsoft.com/applications to invalidate the token server-side. There is no telemetry, no analytics, and no remote logging.
