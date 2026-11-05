# getIPA

**Pull an app off your own jailbroken iPhone and package it as an `.ipa` — in one command.**

`getipa` connects to your device over SSH, lists your recently installed App Store apps (system apps filtered out), and builds a ready-to-use IPA. It automates the manual `ssh` → `cd` → `cp` → `zip` → `scp` routine, and flags the one thing that routine silently gets wrong: FairPlay encryption.

> A tool by [**rudranetra.com**](https://rudranetra.com) · more at [rudranetra.com/tools](https://rudranetra.com/tools)

---

## Features

- **Interactive** – just run `getipa`; it asks for username, device IP and password, then shows your apps.
- **Recent first** – apps sorted by install/update time; system apps (`com.apple.*`) excluded by default.
- **One-shot or scripted** – flags and environment variables for automation.
- **Built-in app report** – permissions, entitlements, ATS settings, URL schemes, frameworks and encryption status, for a fresh extraction or any local IPA.
- **Encrypted *or* decrypted – your choice** – `--decrypted` / `--encrypted` / auto. Decryption is done by [`bagbak`](https://github.com/ChiChou/bagbak), which is **bundled** (installed by `./install.sh`).
- **Hardened against a hostile device** – treats everything coming back from the phone as untrusted (see [Security](#security)).
- **Zero dependencies** – Python 3.8+ standard library and your system `ssh`.

## Requirements

| Where | What |
|---|---|
| Computer | macOS or Linux, Python 3.8+, OpenSSH client (8.4+ for password login) |
| iPhone | Jailbroken, with OpenSSH running (`tar` is included on standard jailbreaks) |
| For decrypted IPAs | Node.js + npm on the computer (bundles `bagbak`), and `frida-server` running on the iPhone |

## Install

**With pipx (recommended):**

```sh
pipx install getipa
getipa --install-bagbak     # one-time: fetches the pinned bagbak (needs Node.js/npm) for decrypted dumps
```

`--install-bagbak` runs `npm ci` against the lockfile shipped in the package and installs into `~/.local/share/getipa` — nothing is installed globally. Skip it if you only want encrypted copies.

**From a clone:**

```sh
git clone https://github.com/RansomWhisker/getIPA.git
cd getIPA
./install.sh            # links getipa into ~/.local/bin AND installs the bundled bagbak
```

`install.sh` does the same pinned `npm ci` (see `getipa_cli/npm/package-lock.json`) inside the clone. Skip it with `SKIP_BAGBAK=1 ./install.sh`.

**For decrypted IPAs you also need `frida-server` on the iPhone:** install it from your jailbreak's package manager (Sileo / Zebra — add the Frida repo `https://build.frida.re` if it isn't listed), make sure it's running, and keep its version in step with the Frida version `bagbak` bundles. If `getipa --decrypted` fails, this is the first thing to check.

> If the bundled install fails, it is almost always Frida's native module not downloading (network reset) or lacking a prebuilt binary for your Node version. Re-run `./install.sh`, or switch to Node 20/22 LTS (`nvm install 22`).

Make sure `~/.local/bin` is on your `PATH` (the installer tells you if it isn't).

## Usage

### Interactive

```sh
getipa
```
```
Username [root]: root
Device IP (just the last number works, e.g. 9 = 192.168.1.9): 9
[*] Using 192.168.1.9
Password (blank = use SSH key/prompt):

Recently installed apps (newest first):
  1. 2026-11-04 18:22  com.example.app        2.4.1      Example
  2. ...
Pick a number (or Enter to quit): 1
[+] Wrote ipas/com.example.app_2.4.1.ipa
```

Shorthand: typing just `9` means `192.168.1.9`, and `0.5` means `192.168.0.5` (works for `--host` too). Full IPs and hostnames are used as typed.

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
| `--info` | Print the app report after extracting |
| `--info-file IPA` | Print the report for a local `.ipa` and exit (no device needed) |
| `--decrypted` / `--encrypted` | Require a decrypted IPA (via bagbak) / take the raw encrypted copy only. Same as `--mode decrypted\|encrypted`. Default `auto`. |
| `--include-system` | Include `com.apple.*` apps |
| `-o DIR` | Output directory (default `./ipas`) |
| `--frida-host` | Let `bagbak` reach `frida-server` over the network |

Environment defaults: `GETIPA_HOST`, `GETIPA_PORT`, `GETIPA_USER`, `SSH_PASSWORD`.

### App report

```sh
getipa --info-file ./ipas/com.example.app_2.4.1.ipa     # offline, any IPA
getipa -b com.example.app --info                         # extract + report
```
```
== Example (com.example.app) ==
Version        2.4.1 (build 301)
Min iOS        15.0
Encrypted      YES (FairPlay, cryptid=1)
ATS            customised: {NSAllowsArbitraryLoads}  <-- insecure
Permissions    2
    NSCameraUsageDescription: Scan codes
Entitlements   2
    aps-environment: production
Frameworks     1
```

## About encryption

Apps installed from the App Store are **FairPlay-encrypted on disk**. A plain file copy gives you an IPA whose main binary can't be disassembled. getIPA lets you choose:

| Mode | What you get |
|---|---|
| `--decrypted` | A decrypted IPA from the running app, via bagbak. Fails with a clear message if bagbak or frida-server is missing. |
| `--encrypted` | The raw copy, named `*_encrypted.ipa`. Fast; fine for inspecting resources, `Info.plist`, entitlements. |
| *auto* (default) | Copies the app; if its binary is encrypted it switches to bagbak, and falls back to the raw copy (with a warning) if that fails. |

In interactive mode, `getipa` asks which one you want after you pick an app.

## Security

`getipa` talks to a device you may not fully trust (jailbroken phones run lots of third-party code), so it validates what comes back:

- Usernames/hosts are validated so they can't be parsed as `ssh` options (no `-oProxyCommand=…` tricks).
- All remote paths are shell-quoted and restricted to the app-container directories.
- The tar stream from the device is extracted defensively: no path traversal, symlinks/hardlinks/devices skipped, permissions normalised.
- Device-supplied names are sanitised before being printed or used in filenames or the `bagbak` command line.
- One SSH connection is opened (control socket in a private `0700` directory) and reused; passwords go to `ssh` via a short-lived `SSH_ASKPASS` helper — never on the command line, never written to disk.
- No telemetry. At runtime the only network traffic is your SSH connection (and Frida, if you ask for a decrypted dump). The bundled `bagbak` is pinned to an exact version with a lockfile; `install.sh` is the only step that downloads anything.

Good hygiene on your side: **change the default `alpine` password**, prefer SSH keys, and only run this on a trusted network. Found a vulnerability? See [SECURITY.md](SECURITY.md).

## Responsible use

For use **only on devices you own and apps you are authorized to analyze** — your own apps, security research, interoperability, and personal backup, where the law permits. Don't use it to pirate software or circumvent licensing. You are responsible for complying with applicable laws and the terms of the software you handle.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `UNIX authentication refused` | Wrong password/user. Try `--user mobile` on rootless jailbreaks. |
| `Too many authentication failures` | Wait a minute / restart OpenSSH on the device; use `--key`. |
| Decrypting fails | Is `frida-server` running on the iPhone? Is its version compatible with bagbak's Frida? Try `--encrypted` for a raw copy. |
| No apps listed | App may live outside `/var/containers/Bundle/Application` (e.g. TrollStore apps). |
| `iTunesMetadata.plist not found` | Normal on many rootless setups; the IPA is still valid. |

## License

[MIT](LICENSE) © Rudranetra India Private Limited — [rudranetra.com](https://rudranetra.com)
