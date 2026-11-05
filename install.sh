#!/bin/sh
# getIPA installer: links `getipa` onto your PATH and bundles bagbak (for decrypted IPAs).
# Usage: ./install.sh [target_dir]        (default: ~/.local/bin)
#        SKIP_BAGBAK=1 ./install.sh       (skip the bagbak/npm step)
set -e
here="$(cd "$(dirname "$0")" && pwd)"
dir="${1:-$HOME/.local/bin}"

mkdir -p "$dir"
chmod +x "$here/getipa"
ln -sf "$here/getipa" "$dir/getipa"
echo "[+] Installed: $dir/getipa"
case ":$PATH:" in *":$dir:"*) ;; *) echo "    Add to PATH: export PATH=\"$dir:\$PATH\"" ;; esac

if [ -n "$SKIP_BAGBAK" ]; then
  echo "[-] Skipping bagbak (SKIP_BAGBAK set). Decrypted dumps will be unavailable."
  exit 0
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "[!] npm not found - install Node.js (v20 or v22 LTS recommended) and re-run,"
  echo "    otherwise getipa can only make encrypted copies."
  exit 0
fi

echo "[*] Installing bundled bagbak (pinned version, from package-lock.json) ..."
if (cd "$here/getipa_cli/npm" && npm ci --omit=dev --no-fund --no-audit >/dev/null 2>&1) \
   || (cd "$here/getipa_cli/npm" && npm install --omit=dev --no-fund --no-audit >/dev/null 2>&1); then
  echo "[+] bagbak ready."
else
  echo "[!] bagbak failed to install (Node $(node --version 2>/dev/null))."
  echo "    This is usually Frida's native module failing to download (network reset or"
  echo "    blocked host) or having no prebuilt binary for your Node version. Try:"
  echo "      1. re-run ./install.sh (downloads are cached once one succeeds)"
  echo "      2. use Node 20 or 22 LTS ('nvm install 22 && nvm use 22'), then re-run"
  echo "    getipa still works for encrypted copies in the meantime."
fi
echo
echo "Decrypted dumps also need frida-server running on the iPhone (install it from your"
echo "jailbreak's package manager: Sileo/Zebra). See README for details."
