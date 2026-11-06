"""getipa: pull an app from a jailbroken iPhone over SSH and package it as an .ipa.

Intended for apps you own / are authorized to analyze, on a device you own.

Usage:
  getipa --host 192.168.1.20 --list
  getipa --host 192.168.1.20 --bundle-id com.example.app [-o out_dir]
  # USB via iproxy (iproxy 2222 22):
  getipa --host 127.0.0.1 --port 2222 --list

Env defaults: GETIPA_HOST, GETIPA_PORT, GETIPA_USER.
Auth: use SSH keys (recommended) or a password (prompted, or via SSH_PASSWORD; needs OpenSSH 8.4+).
Stdlib only. Requires `ssh` locally and tar on the device (standard on jailbreaks).

Note: App Store binaries are FairPlay-encrypted on disk. A plain copy yields an IPA
whose main binary has cryptid=1 and won't be usable for analysis. If detected, the
tool delegates to `bagbak` (npm i -g bagbak) when installed, which dumps decrypted
binaries via Frida.
"""
from . import __version__
import argparse
import os
import plistlib
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

APP_ROOTS = ("/var/containers/Bundle/Application/", "/private/var/containers/Bundle/Application/")
USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$")
HOST_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._:\-]{0,252}$")   # no leading '-', no spaces
BUNDLE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def expand_host(text):
    """Shorthand for the common home-LAN range:  9 -> 192.168.1.9,  0.5 -> 192.168.0.5.
    Anything else (full IPs, hostnames, localhost) is returned unchanged."""
    text = text.strip()
    if re.fullmatch(r"\d{1,3}", text):
        parts = ["1", text]
    elif re.fullmatch(r"\d{1,3}\.\d{1,3}", text):
        parts = text.split(".")
    else:
        return text
    if all(int(x) <= 255 for x in parts):
        return "192.168." + ".".join(str(int(x)) for x in parts)
    return text


NPM_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "npm")


def data_dir():
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "getipa")


def _bin(root):
    for name in ("bagbak.cmd", "bagbak") if os.name == "nt" else ("bagbak",):
        p = os.path.join(root, "node_modules", ".bin", name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def find_bagbak():
    """Order: copy next to the package (git clone / install.sh), per-user copy made by
    `getipa --install-bagbak` (pip/pipx installs), then PATH."""
    return _bin(NPM_DIR) or _bin(data_dir()) or shutil.which("bagbak")


def install_bagbak():
    """Install the pinned bagbak (package-lock.json) into the per-user data dir."""
    npm = shutil.which("npm")
    if not npm:
        print("[!] npm not found. Install Node.js (v20 or v22 LTS recommended), then run "
              "`getipa --install-bagbak` again. Encrypted copies work without it.")
        return False
    dest = data_dir()
    os.makedirs(dest, mode=0o700, exist_ok=True)
    for f in ("package.json", "package-lock.json"):
        shutil.copyfile(os.path.join(NPM_DIR, f), os.path.join(dest, f))
    print(f"[*] Installing pinned bagbak into {dest} ...")
    for cmd in ([npm, "ci", "--omit=dev", "--no-fund", "--no-audit"],
                [npm, "install", "--omit=dev", "--no-fund", "--no-audit"]):
        if subprocess.run(cmd, cwd=dest, stdout=subprocess.DEVNULL).returncode == 0 and _bin(dest):
            print("[+] bagbak ready.")
            return True
    print("[!] bagbak failed to install (usually Frida's native module failing to download, "
          "or no prebuilt binary for your Node version). Retry, or use Node 20/22 LTS.")
    return False


def run_bagbak(a, bagbak, bid, out_dir):
    """Run bagbak for bundle id `bid`. Returns True on success."""
    if not BUNDLE_ID_RE.match(bid):
        print("[!] Refusing to pass an unusual bundle id to bagbak.")
        return False
    os.makedirs(out_dir, exist_ok=True)
    host_args = ["-H", a.host] if a.frida_host else []
    return subprocess.run([bagbak, *host_args, "-o", out_dir, bid]).returncode == 0


def clean(text):
    """Strip control/escape characters from device-supplied text before printing."""
    return _CTRL_RE.sub("?", str(text))


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(text))[:100] or "app"


_SOCK = None
_ENV = None            # child environment carrying the password (only when connections are not shared)
IS_WIN = os.name == "nt"
# OpenSSH on Windows has no ControlMaster, so there each command logs in separately.
SHARE_CONNECTION = not IS_WIN


def private_tmpdir(prefix):
    """0700 temp dir. /tmp (when it exists) keeps Unix-socket paths short on macOS."""
    return tempfile.mkdtemp(prefix=prefix, dir="/tmp" if os.path.isdir("/tmp") else None)


def make_askpass(tmp, var, password):
    """SSH_ASKPASS helper + environment. The password lives only in the child's
    environment, never in the helper file or on a command line."""
    if IS_WIN:
        py = os.path.join(tmp, "askpass.py")
        helper = os.path.join(tmp, "askpass.cmd")
        with open(py, "w") as fh:
            fh.write(f"import os, sys\nsys.stdout.write(os.environ[{var!r}] + '\\n')\n")
        with open(helper, "w") as fh:
            fh.write(f'@"{sys.executable}" "{py}"\r\n')
    else:
        helper = os.path.join(tmp, "askpass.sh")
        with open(helper, "w") as fh:
            fh.write(f'#!/bin/sh\nprintf "%s\\n" "${var}"\n')
        os.chmod(helper, 0o700)
    return dict(os.environ, **{var: password}, SSH_ASKPASS=helper, SSH_ASKPASS_REQUIRE="force")


def _base(a):
    base = ["ssh", "-p", str(a.port), "-o", "StrictHostKeyChecking=accept-new",
            "-o", "LogLevel=ERROR"]
    if a.key:
        base += ["-i", a.key, "-o", "IdentitiesOnly=yes"]
    return base + [f"{a.user}@{a.host}"]


def open_master(a):
    """Authenticate once (prompting for the password if needed). On Unix the connection
    is shared for every later call; on Windows each call logs in again."""
    global _SOCK, _ENV
    import atexit
    tmp = private_tmpdir("getipa-")
    env = make_askpass(tmp, "GETIPA_PW", a.password) if a.password else None
    tries = ["-o", "NumberOfPasswordPrompts=1"] if a.password else []
    if SHARE_CONNECTION:
        _SOCK = os.path.join(tmp, "s")
        cmd = _base(a)[:-1] + ["-o", "ControlMaster=yes", "-o", f"ControlPath={_SOCK}",
                               "-o", "ControlPersist=10m", *tries, f"{a.user}@{a.host}", "-fN"]
    else:
        cmd = _base(a)[:-1] + [*tries, f"{a.user}@{a.host}", "true"]
        _ENV = env
    rc = subprocess.run(cmd, env=env).returncode
    if rc != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        sys.exit(f"\nSSH login to {a.user}@{a.host}:{a.port} failed.\n"
                 "  - Wrong password? The jailbreak default is 'alpine' (change it!)\n"
                 "  - Rootless jailbreaks may need --user mobile\n"
                 "  - Check OpenSSH is running on the device, or use --key")

    def _cleanup():
        if SHARE_CONNECTION:
            subprocess.run(["ssh", "-O", "exit", "-o", f"ControlPath={_SOCK}",
                            f"{a.user}@{a.host}"], capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)
    atexit.register(_cleanup)


def ssh_cmd(a):
    if _SOCK:
        return _base(a)[:-1] + ["-o", "ControlMaster=no", "-o", f"ControlPath={_SOCK}",
                                f"{a.user}@{a.host}"]
    return _base(a)


def run_remote(a, command, binary=False):
    p = subprocess.run(ssh_cmd(a) + [command], capture_output=True, env=_ENV)
    if p.returncode != 0:
        sys.exit(f"remote command failed: {p.stderr.decode(errors='replace').strip()}")
    return p.stdout if binary else p.stdout.decode(errors="replace")


def remote_mtimes(a):
    """Map app dir -> install/update epoch time (tries GNU stat, then BSD stat)."""
    globs = ("/var/containers/Bundle/Application/*/*.app "
             "/private/var/containers/Bundle/Application/*/*.app")
    for fmt in ("stat -c '%Y\t%n'", "stat -f '%m\t%N'"):
        p = subprocess.run(ssh_cmd(a) + [f"{fmt} {globs} 2>/dev/null"], capture_output=True, env=_ENV)
        if p.stdout.strip():
            out = {}
            for line in p.stdout.decode(errors="replace").splitlines():
                t, _, path = line.partition("\t")
                if t.isdigit():
                    out[path] = int(t)
            return out
    return {}


def is_system_app(bundle_id):
    return bundle_id.startswith("com.apple.") and bundle_id != "com.apple.TestFlight"


def find_bundles(a, include_system=False):
    """Return [(bundle_id, name, version, app_dir_remote, info, mtime)], newest first.

    /var/containers/Bundle/Application only holds user-installed apps; real system
    apps live in /Applications, so they are never scanned. com.apple.* entries that
    appear here anyway are dropped unless include_system is set.
    """
    mtimes = remote_mtimes(a)
    seen, apps = set(), []
    for app_dir in mtimes or filter(None, run_remote(
            a, "ls -d /var/containers/Bundle/Application/*/*.app 2>/dev/null").splitlines()):
        if not app_dir.startswith(APP_ROOTS) or not app_dir.endswith(".app") \
                or "\n" in app_dir or ".." in app_dir.split("/"):
            continue
        real = app_dir.replace("/private/var", "/var")
        if real in seen:
            continue
        seen.add(real)
        try:
            info = plistlib.loads(run_remote(a, "cat " + shlex.quote(app_dir + "/Info.plist"), binary=True))
        except Exception:
            continue
        bid = str(info.get("CFBundleIdentifier", "?"))
        if not include_system and is_system_app(bid):
            continue
        apps.append((bid,
                     str(info.get("CFBundleDisplayName") or info.get("CFBundleName", "?")),
                     str(info.get("CFBundleShortVersionString", "?")), app_dir, info,
                     mtimes.get(app_dir, 0)))
    apps.sort(key=lambda x: x[5], reverse=True)
    return apps


def fmt_time(t):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else "unknown"


def print_apps(apps):
    for i, (bid, name, ver, _, _, t) in enumerate(apps, 1):
        print(f"{i:3}. {fmt_time(t):16}  {clean(bid):45} {clean(ver):10} {clean(name)}")


def is_encrypted(binary_path):
    """True if any Mach-O slice has LC_ENCRYPTION_INFO(_64) with cryptid != 0.

    The binary is untrusted input: any parse error is treated as 'unknown' (False).
    """
    try:
        return _is_encrypted(binary_path)
    except (struct.error, IndexError, OSError):
        return False


def _is_encrypted(binary_path):
    with open(binary_path, "rb") as f:
        data = f.read(1 << 20)  # load commands live near the start
    magic = struct.unpack(">I", data[:4])[0]
    slices = []
    if magic in (0xCAFEBABE, 0xCAFEBABF):
        n = struct.unpack(">I", data[4:8])[0]
        step = 20 if magic == 0xCAFEBABE else 32
        for i in range(n):
            e = data[8 + i * step: 8 + (i + 1) * step]
            off = struct.unpack(">I", e[8:12])[0] if magic == 0xCAFEBABE else struct.unpack(">Q", e[8:16])[0]
            slices.append(off)
    else:
        slices.append(0)
    for off in slices:
        if off + 32 > len(data):
            with open(binary_path, "rb") as f:
                f.seek(off)
                chunk = f.read(1 << 20)
        else:
            chunk = data[off:]
        m = struct.unpack("<I", chunk[:4])[0]
        if m not in (0xFEEDFACF, 0xFEEDFACE):
            continue
        hdr = 32 if m == 0xFEEDFACF else 28
        ncmds = struct.unpack("<I", chunk[16:20])[0]
        p = hdr
        for _ in range(ncmds):
            cmd, size = struct.unpack("<II", chunk[p:p + 8])
            if cmd in (0x21, 0x2C):
                cryptid = struct.unpack("<I", chunk[p + 16:p + 20])[0]
                if cryptid:
                    return True
            p += size
    return False


def safe_extract(tar_path, dest):
    """Extract a tar from the (untrusted) device: regular files and dirs only,
    nothing may land outside dest. Symlinks/hardlinks/devices are skipped."""
    root = os.path.realpath(dest)
    skipped = 0
    with tarfile.open(tar_path) as t:
        for m in t:
            target = os.path.realpath(os.path.join(root, m.name))
            if not (target == root or target.startswith(root + os.sep)) or os.path.isabs(m.name):
                sys.exit(f"refusing unsafe path in archive: {clean(m.name)!r}")
            if not (m.isreg() or m.isdir()):
                skipped += 1
                continue
            m.mode = (0o755 if m.isdir() or m.mode & 0o111 else 0o644)
            m.uid = m.gid = 0
            if hasattr(tarfile, "data_filter"):
                t.extract(m, root, filter="data")
            else:
                t.extract(m, root)
    if skipped:
        print(f"[!] Skipped {skipped} symlink/special entries (not followed for safety).")


def find_new_ipa(out_dir, since):
    """Newest .ipa in out_dir written at or after `since` (epoch seconds)."""
    best = None
    try:
        for fn in os.listdir(out_dir):
            fp = os.path.join(out_dir, fn)
            if fn.lower().endswith(".ipa") and os.path.getmtime(fp) >= since - 2:
                if best is None or os.path.getmtime(fp) > os.path.getmtime(best):
                    best = fp
    except OSError:
        pass
    return best


def encrypted_binaries(ipa_path):
    """Names of Mach-O files in the IPA (main binary + frameworks) that are still
    FairPlay-encrypted. Returns None if the IPA can't be inspected."""
    import zipfile
    try:
        with zipfile.ZipFile(ipa_path) as z:
            names = z.namelist()
            plist_name = next((n for n in names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n)), None)
            if not plist_name:
                return None
            app_prefix = plist_name.rsplit("/", 1)[0] + "/"
            info = plistlib.loads(z.read(plist_name))
            exe = info.get("CFBundleExecutable")
            cands = [app_prefix + exe] if exe else []
            cands += [n for n in names
                      if re.fullmatch(re.escape(app_prefix) + r"Frameworks/([^/]+)\.framework/\1", n)]
            bad = []
            for n in cands:
                if n not in names:
                    continue
                with tempfile.TemporaryDirectory(prefix="getipa_chk_") as td:
                    fp = os.path.join(td, "bin")
                    with z.open(n) as src, open(fp, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    if is_encrypted(fp):
                        bad.append(n.split("/", 2)[-1])
            return bad
    except (OSError, zipfile.BadZipFile, ValueError, plistlib.InvalidFileException, KeyError):
        return None


def verify_decrypted(out_dir, since):
    """After a bagbak dump: say loudly if the main binary (or a framework) is still encrypted."""
    ipa = find_new_ipa(out_dir, since)
    if not ipa:
        print("[!] Could not find the dumped IPA to verify it.")
        return
    bad = encrypted_binaries(ipa)
    if bad is None:
        print("[!] Could not verify decryption (unreadable IPA).")
    elif bad:
        print(f"[!] WARNING: {os.path.basename(ipa)} is NOT fully decrypted.")
        print("    Still encrypted: " + ", ".join(clean(b) for b in bad[:6]) + (" ..." if len(bad) > 6 else ""))
        print("    Re-run the dump (make sure frida-server is running and matches bagbak's Frida version).")
    else:
        print("[+] Verified: main binary and frameworks are decrypted (cryptid=0).")


def pull_ipa(a, bundle, out_dir):
    bid, name, ver, app_dir, info, _ = bundle
    bagbak = find_bagbak()

    if a.mode == "decrypted":
        # Dump straight from the running app; no need to copy the encrypted bundle first.
        if not bagbak:
            sys.exit("bagbak is not installed. Run `getipa --install-bagbak`, "
                     "or use --mode encrypted.")
        print(f"[*] Dumping decrypted {clean(bid)} with bagbak ...")
        started = time.time()
        if not run_bagbak(a, bagbak, bid, out_dir):
            sys.exit("bagbak failed. Is frida-server running on the device? "
                     "(Use --mode encrypted for a raw copy.)")
        verify_decrypted(out_dir, started)
        return None

    work = tempfile.mkdtemp(prefix="getipa_")
    try:
        parent = os.path.dirname(app_dir)
        app_name = os.path.basename(app_dir)
        print(f"[*] Pulling {clean(app_name)} ({clean(bid)} {clean(ver)}) ...")
        tar_path = os.path.join(work, "app.tar")
        with open(tar_path, "wb") as fh:
            p = subprocess.run(ssh_cmd(a) + [f"cd {shlex.quote(parent)} && tar -cf - {shlex.quote(app_name)}"],
                               stdout=fh, stderr=subprocess.PIPE, env=_ENV)
        if p.returncode != 0:
            sys.exit(f"tar failed: {p.stderr.decode(errors='replace')}")
        payload = os.path.join(work, "Payload")
        os.makedirs(payload)
        safe_extract(tar_path, payload)

        exe = info.get("CFBundleExecutable")
        enc = bool(exe) and is_encrypted(os.path.join(payload, app_name, exe))
        if enc:
            print("[!] Main binary is FairPlay-encrypted (cryptid=1).")
            if a.mode == "encrypted":
                print("    --mode encrypted: keeping the raw (encrypted) copy as requested.")
            elif bagbak:
                print("[*] Switching to bagbak for a decrypted IPA ...")
                started = time.time()
                if run_bagbak(a, bagbak, bid, out_dir):
                    verify_decrypted(out_dir, started)
                    return None
                print("[!] bagbak failed (is frida-server running on the device?); "
                      "falling back to the encrypted copy.")
            else:
                print("    bagbak not found. Run `getipa --install-bagbak`. "
                      "Packaging the encrypted copy anyway.")

        if a.info:
            report_appdir(os.path.join(payload, app_name))
        os.makedirs(out_dir, exist_ok=True)
        ipa = os.path.join(out_dir, f"{safe_name(bid)}_{safe_name(ver)}{'_encrypted' if enc else ''}.ipa")
        with zipfile.ZipFile(ipa, "w", zipfile.ZIP_DEFLATED) as z:
            for root, _, files in os.walk(payload):
                for fn in files:
                    full = os.path.join(root, fn)
                    if os.path.islink(full):
                        continue
                    z.write(full, os.path.relpath(full, work))
            # Include iTunesMetadata.plist if present beside the .app (container root)
            try:
                md = run_remote(a, "cat " + shlex.quote(parent + "/iTunesMetadata.plist"), binary=True)
                z.writestr("iTunesMetadata.plist", md)
            except SystemExit:
                print("[!] Warning: iTunesMetadata.plist not found next to the .app "
                      "(common on rootless jailbreaks); IPA written without it.")
        return ipa
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------- app info report

MAX_EXE_BYTES = 3 << 30  # refuse absurd executables inside an IPA


def get_entitlements(exe_path):
    """Best-effort: parse XML entitlements from the code-signature blob near the end."""
    try:
        with open(exe_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - (4 << 20)))
            tail = f.read()
        for blob in re.findall(rb"<\?xml.*?</plist>", tail, re.S):
            try:
                d = plistlib.loads(blob)
            except Exception:
                continue
            if isinstance(d, dict) and d:
                return d
    except OSError:
        pass
    return {}


def fmt_val(v, limit=70):
    if isinstance(v, (list, tuple)):
        v = ", ".join(clean(x) for x in v)
    elif isinstance(v, dict):
        v = "{" + ", ".join(clean(k) for k in v) + "}"
    v = clean(v)
    return v if len(v) <= limit else v[:limit - 1] + "…"


def report_appdir(app_dir):
    """Print a summary of an unpacked .app directory (or skeleton of one)."""
    try:
        with open(os.path.join(app_dir, "Info.plist"), "rb") as f:
            info = plistlib.load(f)
    except Exception as e:
        print(f"[!] Could not read Info.plist: {clean(e)}")
        return
    exe_name = info.get("CFBundleExecutable")
    exe = os.path.join(app_dir, exe_name) if isinstance(exe_name, str) else None
    families = {1: "iPhone", 2: "iPad", 3: "Apple TV", 4: "Watch"}

    def row(label, value):
        print(f"{label:<15}{value}")

    name = info.get("CFBundleDisplayName") or info.get("CFBundleName", "?")
    print(f"\n== {clean(name)} ({clean(info.get('CFBundleIdentifier', '?'))}) ==")
    row("Version", f"{fmt_val(info.get('CFBundleShortVersionString', '?'))} "
                   f"(build {fmt_val(info.get('CFBundleVersion', '?'))})")
    row("Executable", clean(exe_name or "?"))
    row("Min iOS", fmt_val(info.get("MinimumOSVersion", "?")))
    fam = info.get("UIDeviceFamily")
    if isinstance(fam, list):
        row("Device family", ", ".join(families.get(x, str(x)) for x in fam if isinstance(x, int)))
    if exe and os.path.isfile(exe):
        enc = is_encrypted(exe)
        row("Encrypted", "YES (FairPlay, cryptid=1)" if enc else "no")
    schemes = sorted({sc for t in info.get("CFBundleURLTypes", []) if isinstance(t, dict)
                      for sc in t.get("CFBundleURLSchemes", []) if isinstance(sc, str)})
    if schemes:
        row("URL schemes", fmt_val(schemes, 100))
    if info.get("UIBackgroundModes"):
        row("Background", fmt_val(info["UIBackgroundModes"], 100))
    ats = info.get("NSAppTransportSecurity")
    if isinstance(ats, dict):
        warn = "  <-- insecure" if ats.get("NSAllowsArbitraryLoads") is True else ""
        row("ATS", f"customised: {fmt_val(ats, 80)}{warn}")
    else:
        row("ATS", "default (HTTPS enforced)")
    perms = sorted((k, v) for k, v in info.items()
                   if isinstance(k, str) and k.startswith("NS") and k.endswith("UsageDescription"))
    row("Permissions", f"{len(perms)}")
    for k, v in perms:
        print(f"    {clean(k)}: {fmt_val(v, 60)}")
    ents = get_entitlements(exe) if exe and os.path.isfile(exe) else {}
    row("Entitlements", f"{len(ents)}" if ents else "none found")
    for k in sorted(ents, key=str):
        print(f"    {clean(k)}: {fmt_val(ents[k], 60)}")
    fw_dir = os.path.join(app_dir, "Frameworks")
    fws = sorted(os.listdir(fw_dir)) if os.path.isdir(fw_dir) else []
    row("Frameworks", f"{len(fws)}")
    if fws:
        print("    " + fmt_val(fws, 200))
    row("Provisioning", "embedded.mobileprovision present"
        if os.path.exists(os.path.join(app_dir, "embedded.mobileprovision")) else "none")
    print()


def report_ipa(ipa_path):
    """Inspect a local IPA without unpacking it wholesale."""
    if not os.path.isfile(ipa_path):
        sys.exit(f"not a file: {ipa_path}")
    work = tempfile.mkdtemp(prefix="getipa_info_")
    try:
        with zipfile.ZipFile(ipa_path) as z:
            names = z.namelist()
            apps = {m.group(1) for n in names
                    if (m := re.match(r"^Payload/([^/]+\.app)/Info\.plist$", n))}
            if len(apps) != 1:
                sys.exit("This does not look like an IPA (expected one Payload/<name>.app).")
            app = apps.pop()
            skel = os.path.join(work, "app.app")  # fixed local name: never trust zip paths
            os.makedirs(skel)

            def copy(member, dest):
                zi = z.getinfo(member)
                if zi.file_size > MAX_EXE_BYTES:
                    sys.exit(f"refusing oversized member: {clean(member)}")
                with z.open(zi) as src, open(dest, "wb") as out:
                    shutil.copyfileobj(src, out)

            copy(f"Payload/{app}/Info.plist", os.path.join(skel, "Info.plist"))
            with open(os.path.join(skel, "Info.plist"), "rb") as f:
                exe_name = plistlib.load(f).get("CFBundleExecutable")
            if isinstance(exe_name, str) and f"Payload/{app}/{exe_name}" in names \
                    and "/" not in exe_name:
                copy(f"Payload/{app}/{exe_name}", os.path.join(skel, exe_name))
            for n in names:
                m = re.match(rf"^Payload/{re.escape(app)}/Frameworks/([^/]+)/$", n) or \
                    re.match(rf"^Payload/{re.escape(app)}/Frameworks/([^/]+)/[^/]+$", n)
                if m:
                    os.makedirs(os.path.join(skel, "Frameworks", safe_name(m.group(1))), exist_ok=True)
            if f"Payload/{app}/embedded.mobileprovision" in names:
                open(os.path.join(skel, "embedded.mobileprovision"), "wb").close()
        print(f"IPA: {clean(os.path.basename(ipa_path))}")
        report_appdir(skel)
    except zipfile.BadZipFile:
        sys.exit("not a valid zip/IPA file")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    for _s in (sys.stdout, sys.stderr):      # Windows consoles default to a legacy codepage
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=os.environ.get("GETIPA_HOST"),
                    help="device IP/host (or set GETIPA_HOST)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("GETIPA_PORT", 22)))
    ap.add_argument("--user", default=os.environ.get("GETIPA_USER", "root"))
    ap.add_argument("--key", help="SSH private key path")
    ap.add_argument("--list", action="store_true", help="list user-installed apps, newest first")
    ap.add_argument("--all", action="store_true", help="show every app (default: 10 most recent)")
    ap.add_argument("-n", "--recent", type=int, default=10, help="how many recent apps to show")
    ap.add_argument("--include-system", action="store_true", help="include com.apple.* apps")
    ap.add_argument("--bundle-id", "-b", help="bundle id (or substring) to extract")
    ap.add_argument("-o", "--out", default="./ipas")
    ap.add_argument("--mode", choices=["auto", "decrypted", "encrypted"], default="auto",
                    help="auto: decrypt if possible, else raw copy (default) | "
                         "decrypted: require a decrypted IPA | encrypted: raw copy only")
    ap.add_argument("--decrypted", dest="mode", action="store_const", const="decrypted",
                    help="shortcut for --mode decrypted")
    ap.add_argument("--encrypted", dest="mode", action="store_const", const="encrypted",
                    help="shortcut for --mode encrypted")
    ap.add_argument("--info", action="store_true",
                    help="print an app report (permissions, entitlements, ATS...) after extracting")
    ap.add_argument("--info-file", metavar="IPA",
                    help="print the report for a local .ipa and exit (no device needed)")
    ap.add_argument("--frida-host", action="store_true",
                    help="have bagbak connect to frida-server over the network at --host")
    ap.add_argument("--install-bagbak", action="store_true",
                    help="install the pinned bagbak (needs Node.js/npm) for decrypted dumps, then exit")
    ap.add_argument("--version", action="version", version=f"getipa {__version__}")
    a = ap.parse_args()
    if a.install_bagbak:
        sys.exit(0 if install_bagbak() else 1)
    if a.info_file:
        report_ipa(a.info_file)
        return
    a.password = os.environ.get("SSH_PASSWORD")
    if not a.host:
        if not sys.stdin.isatty():
            ap.error("--host is required (or set GETIPA_HOST)")
        import getpass
        a.user = input(f"Username [{a.user}]: ").strip() or a.user
        a.host = input("Device IP (just the last number works, e.g. 9 = 192.168.1.9): ").strip()
        if not a.host:
            sys.exit("An IP address is required.")
        a.password = getpass.getpass("Password (blank = use SSH key/prompt): ") or None

    expanded = expand_host(a.host)
    if expanded != a.host:
        print(f"[*] Using {expanded}")
        a.host = expanded
    if not USER_RE.match(a.user) or not HOST_RE.match(a.host):
        sys.exit("Invalid username or host.")
    if not 0 < a.port < 65536:
        sys.exit("Invalid port.")
    if a.key and not os.path.isfile(a.key):
        sys.exit(f"SSH key not found: {a.key}")
    open_master(a)
    apps = find_bundles(a, a.include_system)
    shown = apps if a.all else apps[:a.recent]
    if a.list:
        print_apps(shown)
        return
    if not a.bundle_id:
        if not sys.stdin.isatty():
            print_apps(shown)
            return
        print("Recently installed apps (newest first):")
        print_apps(shown)
        choice = input("Pick a number (or Enter to quit): ").strip()
        if not choice.isdigit() or not 1 <= int(choice) <= len(shown):
            return
        matches = [shown[int(choice) - 1]]
        if a.mode == "auto":
            have = find_bagbak() is not None
            print("\nExtract as:")
            print(f"  1) Decrypted IPA  (recommended; {'bagbak found' if have else 'bagbak NOT installed - run getipa --install-bagbak'})")
            print("  2) Encrypted IPA  (raw copy, fastest, not analyzable)")
            m = input("Choice [1]: ").strip() or "1"
            a.mode = "encrypted" if m == "2" else "decrypted"
    else:
        matches = [x for x in apps if a.bundle_id == x[0]] or \
                  [x for x in apps if a.bundle_id.lower() in x[0].lower() or a.bundle_id.lower() in x[1].lower()]
        if not matches:
            sys.exit(f"no app matching '{clean(a.bundle_id)}'. Use --list.")
        if len(matches) > 1:
            print("Multiple matches:")
            print_apps(matches)
            sys.exit(1)
    ipa = pull_ipa(a, matches[0], a.out)
    if ipa:
        print(f"[+] Wrote {ipa}")


if __name__ == "__main__":
    main()
