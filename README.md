# getIPA

**Pull an app off your own jailbroken iPhone and package it as an `.ipa` — in one command.**

`getipa` connects to your device over SSH, lists your recently installed App Store apps (system apps filtered out), and builds a ready-to-use IPA. It automates the manual `ssh` → `cd` → `cp` → `zip` → `scp` routine, and flags the one thing that routine silently gets wrong: FairPlay encryption.

> A tool by [**rudranetra.com**](https://rudranetra.com) · more at [rudranetra.com/tools](https://rudranetra.com/tools)

---

## Features

- **Interactive** – just run `getipa`; it asks for username, device IP and password, then shows your apps.
- **Recent first** – apps sorted by install/update time; system apps (`com.apple.*`) excluded by default.
- **One-shot or scripted** – flags and environment variables for automation.
- **Encryption-aware** – detects FairPlay-encrypted binaries (`cryptid=1`) and hands off to [`bagbak`](https://github.com/ChiChou/bagbak) for a decrypted dump when installed.
- **Hardened against a hostile device** – treats everything coming back from the phone as untrusted (see [Security](#security)).
- **Zero dependencies** – Python 3.8+ standard library and your system `ssh`.

## Requirements

| Where | What |
|---|---|
| Computer | macOS or Linux, Python 3.8+, OpenSSH client (8.4+ for password login) |
| iPhone | Jailbroken, with OpenSSH running (`tar` is included on standard jailbreaks) |
| Optional | [`bagbak`](https://github.com/ChiChou/bagbak) + `frida-server` on the device, to get *decrypted* IPAs |

## Install

```sh
git clone https://github.com/RansomWhisker/getIPA.git
cd getIPA
./install.sh            # symlinks getipa into ~/.local/bin
```

Make sure `~/.local/bin` is on your `PATH` (the installer tells you if it isn't).

## Usage

### Interactive

```sh
getipa
```
```
Username [root]: root
Device IP (e.g. 192.168.1.x): 192.168.1.9
Password (blank = use SSH key/prompt):

Recently installed apps (newest first):
  1. 2026-11-04 18:22  com.example.app        2.4.1      Example
  2. ...
Pick a number (or Enter to quit): 1
[+] Wrote ipas/com.example.app_2.4.1.ipa
```

### Flags

```sh
getipa --host 192.168.1.9 --list                 # list only
getipa --host 192.168.1.9 -b com.example.app     # by bundle ID or name substring
getipa --host 127.0.0.1 --port 2222 --list       # USB via `iproxy 2222 22`
getipa --host 192.168.1.9 --key ~/.ssh/id_ed25519 -n 25
```

| Option | Description |
|---|---|
| `--host`, `--port`, `--user` | Connection details (defaults: port `22`, user `root`) |
| `--key PATH` | SSH private key (recommended over passwords) |
| `--list` | List apps and exit |
| `-n N` / `--all` | Show the N most recent apps (default 10) / everything |
| `-b`, `--bundle-id` | Extract an app by bundle ID or name |
| `--include-system` | Include `com.apple.*` apps |
| `-o DIR` | Output directory (default `./ipas`) |
| `--frida-host` | Let `bagbak` reach `frida-server` over the network |

Environment defaults: `GETIPA_HOST`, `GETIPA_PORT`, `GETIPA_USER`, `SSH_PASSWORD`.

## About encryption

Apps installed from the App Store are **FairPlay-encrypted on disk**. Copying the bundle (which is all the manual method does) gives you an IPA whose main binary can't be disassembled. `getipa` checks for this:

- Encrypted + `bagbak` installed → a decrypted IPA is produced via Frida.
- Encrypted, no `bagbak` → the IPA is still written, named `*_encrypted.ipa`, with instructions.

## Security

`getipa` talks to a device you may not fully trust (jailbroken phones run lots of third-party code), so it validates what comes back:

- Usernames/hosts are validated so they can't be parsed as `ssh` options (no `-oProxyCommand=…` tricks).
- All remote paths are shell-quoted and restricted to the app-container directories.
- The tar stream from the device is extracted defensively: no path traversal, symlinks/hardlinks/devices skipped, permissions normalised.
- Device-supplied names are sanitised before being printed or used in filenames or the `bagbak` command line.
- One SSH connection is opened (control socket in a private `0700` directory) and reused; passwords go to `ssh` via a short-lived `SSH_ASKPASS` helper — never on the command line, never written to disk.
- No telemetry, no network access other than your SSH connection.

Good hygiene on your side: **change the default `alpine` password**, prefer SSH keys, and only run this on a trusted network. Found a vulnerability? See [SECURITY.md](SECURITY.md).

## Responsible use

For use **only on devices you own and apps you are authorized to analyze** — your own apps, security research, interoperability, and personal backup, where the law permits. Don't use it to pirate software or circumvent licensing. You are responsible for complying with applicable laws and the terms of the software you handle.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `UNIX authentication refused` | Wrong password/user. Try `--user mobile` on rootless jailbreaks. |
| `Too many authentication failures` | Wait a minute / restart OpenSSH on the device; use `--key`. |
| No apps listed | App may live outside `/var/containers/Bundle/Application` (e.g. TrollStore apps). |
| `iTunesMetadata.plist not found` | Normal on many rootless setups; the IPA is still valid. |

## License

[MIT](LICENSE) © Rudranetra India Private Limited — [rudranetra.com](https://rudranetra.com)
