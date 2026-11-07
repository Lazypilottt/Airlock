# Security policy

Airlock is a security tool, so reports about it are very welcome.

## Reporting a vulnerability

Please **do not** open a public issue for a vulnerability in Airlock itself
(for example a way to make Airlock crash, leak secrets into its logs, approve
something without the user, or let traffic bypass its checks).

Report it privately through GitHub: **Security → Report a vulnerability** on
this repository. Include what you did, what you expected, what happened, and
the Airlock version (`pip show airlock-mcp`).

You will get an acknowledgement within 5 working days. Fixes are released as
soon as they are ready; you will be credited in the changelog unless you ask
not to be.

## Bypasses that are already known

Attacks Airlock does not catch by design are listed in
`docs/known-issues.md` (Limits). A new way around taint tracking or the
detectors that is not on that list is welcome as a normal issue using the
"Bypass" template, unless it also breaks Airlock itself (then report
privately).

## Supported versions

The latest release receives fixes.
