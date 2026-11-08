# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **"Report a vulnerability"** form (Security tab
of this repository) instead of a public issue. Include the affected version, steps to reproduce, and the
impact you expect.

You can expect an acknowledgement within 7 days. Once a fix is available, the report is disclosed
together with the release that fixes it.

## Scope

Of particular interest:

- command injection into `adb shell` commands
- sensitive data reaching disk or exports despite redaction being enabled
- session files readable by other users on a shared host
- path traversal through session references or export destinations

mobile-bridge diagnoses devices and apps you are authorized to debug. Reports about bypassing mobile OS
security controls with this tool are out of scope, because the tool does not attempt it.
