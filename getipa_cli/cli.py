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
import json
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


_IOS_DEVICE: dict = {}


def ios_frida_device(a, root):
    """Frida id of the USB iPhone, or None. Avoids bagbak/Frida picking a plugged-in Android phone."""
    if a.frida_host:
        return None
    if "id" in _IOS_DEVICE:
        return _IOS_DEVICE["id"]
    helper, node = os.path.join(root, "devices.mjs"), shutil.which("node")
    found = None
    if node and os.path.isdir(os.path.join(root, "node_modules", "frida")):
        try:
            if helper != os.path.join(NPM_DIR, "devices.mjs"):
                shutil.copyfile(os.path.join(NPM_DIR, "devices.mjs"), helper)
            p = subprocess.run([node, helper], cwd=root, capture_output=True, timeout=30)
            ids = json.loads(p.stdout.decode().strip().splitlines()[-1]) if p.returncode == 0 else []
            if len(ids) == 1 and re.fullmatch(r"[A-Za-z0-9._:-]{8,100}", ids[0]):
                found = ids[0]
        except (subprocess.TimeoutExpired, ValueError, IndexError, OSError):
            pass
    _IOS_DEVICE["id"] = found
    return found


def run_bagbak(a, bagbak, bid, out_dir, mode=None):
    """Run bagbak for bundle id `bid`. Returns True on success."""
    if not BUNDLE_ID_RE.match(bid):
        print("[!] Refusing to pass an unusual bundle id to bagbak.")
        return False
    os.makedirs(out_dir, exist_ok=True)
    host_args = ["-H", a.host] if a.frida_host else []
    dev = ios_frida_device(a, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(bagbak)))))
    if dev:
        host_args = ["-D", dev]
    return subprocess.run([bagbak, *host_args, "-o", out_dir, bid, *([mode] if mode else [])]).returncode == 0


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


def encrypted_binaries(ipa_path, include_extensions=False):
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
            if include_extensions:
                for pl in (n for n in names if re.fullmatch(re.escape(app_prefix) + r"PlugIns/[^/]+\.appex/Info\.plist", n)):
                    try:
                        ex = plistlib.loads(z.read(pl)).get("CFBundleExecutable")
                    except Exception:
                        continue
                    if ex:
                        cands.append(pl.rsplit("/", 1)[0] + "/" + ex)
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


# ------------------------------------------------ repair leftover encrypted pages

def macho_encryption_layout(data):
    """For a thin or fat Mach-O (bytes), return a list of dicts, one per slice that has a
    LC_ENCRYPTION_INFO(_64): slice_off, lc_off, cryptoff, cryptsize, cryptid, segments."""
    slices = []
    if len(data) < 32:
        return slices
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic in (0xBEBAFECA, 0xBFBAFECA):                       # fat (big-endian header)
        wide = magic == 0xBFBAFECA
        n = struct.unpack_from(">I", data, 4)[0]
        esz = 32 if wide else 20
        for i in range(min(n, 8)):
            base = 8 + i * esz
            off = struct.unpack_from(">Q" if wide else ">I", data, base + (8 if wide else 8))[0]
            slices.append(off)
    else:
        slices.append(0)
    out = []
    for so in slices:
        if so + 32 > len(data) or struct.unpack_from("<I", data, so)[0] != 0xFEEDFACF:   # 64-bit only
            continue
        ncmds = struct.unpack_from("<I", data, so + 16)[0]
        o, segs, enc = so + 32, [], None
        for _ in range(min(ncmds, 4096)):
            if o + 8 > len(data):
                break
            cmd, size = struct.unpack_from("<II", data, o)
            if cmd == 0x19 and o + 56 <= len(data):
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, o + 24)
                segs.append((vmaddr, vmsize, fileoff, filesize))
            elif cmd == 0x2C and o + 24 <= len(data):
                cryptoff, cryptsize, cryptid = struct.unpack_from("<III", data, o + 8)
                enc = (o, cryptoff, cryptsize, cryptid)
            if size < 8:
                break
            o += size
        if enc and enc[3] != 0:
            out.append({"slice_off": so, "lc_off": enc[0], "cryptoff": enc[1], "cryptsize": enc[2],
                        "cryptid": enc[3], "segments": segs})
    return out


def runtime_offset(segments, fileoff):
    """Offset from the module's load address for a file offset (module base == first segment with vmaddr>0)."""
    text_vm = next((s[0] for s in segments if s[0] > 0), None)
    for vmaddr, vmsize, foff, fsize in segments:
        if fsize and foff <= fileoff < foff + fsize and text_vm is not None:
            return vmaddr - text_vm + (fileoff - foff)
    return None


def _entropy(b):
    import math
    from collections import Counter
    if not b:
        return 0.0
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in Counter(b).values())


def repair_encrypted_ipa(a, ipa_path, bid, bad):
    """bagbak sometimes leaves a small FairPlay region untouched (cryptid stays 1). The decrypted
    bytes are in the running app's memory, so read just those ranges with Frida (read-only),
    patch them into the IPA and clear cryptid. Returns True if something was repaired."""
    node = shutil.which("node")
    for root in (NPM_DIR, data_dir()):
        if os.path.isdir(os.path.join(root, "node_modules", "frida")):
            break
    else:
        return False
    if not node or not BUNDLE_ID_RE.match(bid):
        return False
    with zipfile.ZipFile(ipa_path) as z:
        names = z.namelist()
        plist_name = next(n for n in names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n))
        prefix = plist_name.rsplit("/", 1)[0] + "/"
        exe = plistlib.loads(z.read(plist_name)).get("CFBundleExecutable")
        targets = {}                                   # zip name -> (module or None, bytes, layouts)
        for n in bad:
            full = prefix + n
            data = bytearray(z.read(full))
            layouts = macho_encryption_layout(bytes(data))
            if layouts:
                module = None if n == exe else os.path.basename(n)
                targets[full] = (module, data, layouts)
    if not targets:
        return False
    plan, jobs = [], []
    for full, (module, data, layouts) in targets.items():
        for lay in layouts:
            off = runtime_offset(lay["segments"], lay["cryptoff"])
            if off is None or lay["cryptsize"] > (256 << 20):
                continue
            plan.append((full, lay))
            jobs.append({"module": module, "off": off, "size": lay["cryptsize"]})
    if not jobs:
        return False
    helper = os.path.join(root, "repair.mjs")
    shutil.copyfile(os.path.join(NPM_DIR, "repair.mjs"), helper) if helper != os.path.join(NPM_DIR, "repair.mjs") else None
    cmd = [node, helper, bid, json.dumps(jobs)] + ([a.host] if a.frida_host else [])
    print("[*] Reading the still-encrypted region(s) from the running app (read-only) ...")
    blobs = None
    for delay in ("3500", "1200", "400", "-1"):        # apps that quit quickly (jailbreak checks) need an earlier read
        try:
            env = dict(os.environ)
            env["GETIPA_DELAY_MS"] = delay
            dev = ios_frida_device(a, root)
            if dev:
                env["GETIPA_DEVICE"] = dev
            p = subprocess.run(cmd, cwd=root, capture_output=True, timeout=120, env=env)
            blobs = json.loads(p.stdout.decode().strip().splitlines()[-1]) if p.returncode == 0 else None
            if p.returncode != 0:
                msg = [l for l in p.stderr.decode("utf-8", "replace").splitlines() if "Error" in l or "error" in l]
                if msg:
                    print("    " + clean(msg[-1].strip())[:160] + f"  (waited {delay} ms)")
        except (subprocess.TimeoutExpired, ValueError, IndexError, OSError):
            blobs = None
        if blobs and len(blobs) == len(plan):
            break
    if not blobs or len(blobs) != len(plan):
        print("[!] Could not read the decrypted pages from the device.")
        return False
    import base64
    for (full, lay), b64 in zip(plan, blobs):
        mem = base64.b64decode(b64)
        if len(mem) != lay["cryptsize"] or _entropy(mem) >= 7.5:
            print("[!] The device returned data that still looks encrypted; leaving the IPA unchanged.")
            return False
        data = targets[full][1]
        start = lay["slice_off"] + lay["cryptoff"]
        data[start:start + len(mem)] = mem
        struct.pack_into("<I", data, lay["lc_off"] + 16, 0)           # cryptid = 0
    tmp = ipa_path + ".repairing"
    with zipfile.ZipFile(ipa_path) as zin, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename in targets:
                zout.writestr(item, bytes(targets[item.filename][1]))
            else:
                zout.writestr(item, zin.read(item.filename))
    os.replace(tmp, ipa_path)
    print(f"[+] Repaired {len(plan)} encrypted region(s) from the running app.")
    return True


def report_decryption(ipa, a=None, bid=None):
    """Say loudly if the main binary (or a framework) of `ipa` is still encrypted."""
    bad = encrypted_binaries(ipa)
    if bad and a is not None and bid:
        print("[!] Some binaries are still encrypted after the dump (cryptid=1).")
        try:
            if repair_encrypted_ipa(a, ipa, bid, bad):
                bad = encrypted_binaries(ipa)
        except (OSError, zipfile.BadZipFile, StopIteration, ValueError, KeyError, struct.error) as e:
            print(f"[!] Repair failed: {type(e).__name__}: {e}")
    if bad is None:
        print("[!] Could not verify decryption (unreadable IPA).")
    elif bad:
        print(f"[!] WARNING: {os.path.basename(ipa)} is NOT fully decrypted.")
        print("    Still encrypted: " + ", ".join(clean(b) for b in bad[:6]) + (" ..." if len(bad) > 6 else ""))
        print("    Re-run the dump (make sure frida-server is running and matches bagbak's Frida version).")
    else:
        print("[+] Verified: main binary and frameworks are decrypted (cryptid=0).")
        ext = encrypted_binaries(ipa, include_extensions=True) or []
        ext = [e for e in ext if ".appex/" in e]
        if ext:
            print("[i] App extensions still encrypted (rarely matter for analysis): "
                  + ", ".join(clean(os.path.basename(os.path.dirname(e))) for e in ext[:6]))


def verify_decrypted(out_dir, since, a=None, bid=None):
    """After a bagbak dump: find the new IPA and verify it."""
    ipa = find_new_ipa(out_dir, since)
    if not ipa:
        print("[!] Could not find the dumped IPA to verify it.")
        return
    report_decryption(ipa, a, bid)


def decrypted_main_binary(a, bagbak, bid, exe):
    """Fallback when a full bagbak dump fails (often on an app extension): dump only the
    main app and return the path of the decrypted main executable (inside a temp dir), or None."""
    tmp = tempfile.mkdtemp(prefix="getipa_main_")
    if not run_bagbak(a, bagbak, bid, tmp, mode="main"):
        shutil.rmtree(tmp, ignore_errors=True)
        return None
    for fn in os.listdir(tmp):
        if fn.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(os.path.join(tmp, fn)) as z:
                    name = "binaries/" + exe
                    if name in z.namelist():
                        dest = os.path.join(tmp, "main_exe")
                        with z.open(name) as src, open(dest, "wb") as out:
                            shutil.copyfileobj(src, out)
                        return dest
            except (OSError, zipfile.BadZipFile):
                pass
    shutil.rmtree(tmp, ignore_errors=True)
    return None


def pull_ipa(a, bundle, out_dir):
    bid, name, ver, app_dir, info, _ = bundle
    bagbak = find_bagbak()
    main_exe = None

    if a.mode == "decrypted":
        # Dump straight from the running app; no need to copy the encrypted bundle first.
        if not bagbak:
            sys.exit("bagbak is not installed. Run `getipa --install-bagbak`, "
                     "or use --mode encrypted.")
        print(f"[*] Dumping decrypted {clean(bid)} with bagbak ...")
        started = time.time()
        if run_bagbak(a, bagbak, bid, out_dir):
            verify_decrypted(out_dir, started, a, bid)
            return None
        print("[!] The full dump failed (often an app extension that can't be spawned).")
        print("[*] Retrying with the main app only; extensions will stay as the installed copy ...")
        main_exe = decrypted_main_binary(a, bagbak, bid, info.get("CFBundleExecutable") or "")
        if not main_exe:
            sys.exit("bagbak failed. Is frida-server running on the device (and does its version match "
                     "bagbak's Frida)? Use --mode encrypted for a raw copy.")

    try_repair = False
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
        if main_exe and exe:
            shutil.copyfile(main_exe, os.path.join(payload, app_name, exe))
            shutil.rmtree(os.path.dirname(main_exe), ignore_errors=True)
            print("[+] Replaced the main binary with the decrypted one.")
        enc = bool(exe) and is_encrypted(os.path.join(payload, app_name, exe))
        if enc:
            print("[!] Main binary is FairPlay-encrypted (cryptid=1).")
            if a.mode == "encrypted":
                print("    --mode encrypted: keeping the raw (encrypted) copy as requested.")
            elif bagbak and not main_exe:
                print("[*] Switching to bagbak for a decrypted IPA ...")
                started = time.time()
                if run_bagbak(a, bagbak, bid, out_dir):
                    verify_decrypted(out_dir, started, a, bid)
                    return None
                print("[!] bagbak failed (is frida-server running on the device?); "
                      "falling back to the encrypted copy.")
                try_repair = True        # still try to read the decrypted pages straight from the app
            elif not bagbak:
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
        if a.mode == "decrypted" or try_repair:
            if try_repair:
                print("[*] Trying to recover the decrypted code from the app directly ...")
            report_decryption(ipa, a, bid)
            if enc and encrypted_binaries(ipa) == [] and ipa.endswith("_encrypted.ipa"):
                fixed = ipa[:-len("_encrypted.ipa")] + ".ipa"
                os.replace(ipa, fixed)
                ipa = fixed
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
