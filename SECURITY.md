# Security policy

This repository contains a generic installer and no server addresses, private keys, tokens, passwords, or application configuration.

## Installation safety

- Download an installer from an immutable commit URL.
- Verify its SHA-256 digest before running it as root.
- Review changes when the digest or source commit changes.
- Never use a moving `main` URL in unattended automation.
- Treat the one-time enrollment token as short-lived sensitive data: generate it randomly, never log it, keep it mode `0600`, and remove both target and controller copies immediately after successful first-contact verification.

## Reporting

Report vulnerabilities through GitHub private vulnerability reporting when enabled. Do not include production credentials or private server data in an issue.
