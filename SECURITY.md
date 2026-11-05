# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
"Report a vulnerability" (Security tab → Advisories) on this repository, or
contact me via [rudranetra.com](https://rudranetra.com).

Include steps to reproduce and the impact. I'll acknowledge reports promptly and
credit reporters who want it.

## Scope

`getipa` treats the connected device as untrusted input. Reports about path
traversal, command/option injection, unsafe archive handling, credential
exposure, or terminal-escape injection are especially welcome.

## Out of scope

Weak device configuration (e.g. the default `alpine` password), and issues in
third-party tools such as `bagbak`, Frida or OpenSSH.
