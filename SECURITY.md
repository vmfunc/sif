# security policy

## reporting a vulnerability

if you find a security issue in sif, email celeste@linux.com directly.
don't open a public issue.

expect a response within 48 hours. if it's confirmed, i'll push a fix
and credit you in the release notes (unless you'd rather stay anonymous).

## scope

sif is a pentesting tool — "it can scan things" is not a vulnerability.
actual bugs: command injection in user input handling, path traversal in
template extraction, credential leaks, that kind of thing.
