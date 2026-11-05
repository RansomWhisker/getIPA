#!/bin/sh
# Install getipa onto PATH (symlink). Usage: ./install.sh [target_dir]
set -e
src="$(cd "$(dirname "$0")" && pwd)/getipa"
dir="${1:-$HOME/.local/bin}"
mkdir -p "$dir"
chmod +x "$src"
ln -sf "$src" "$dir/getipa"
echo "Installed: $dir/getipa"
case ":$PATH:" in *":$dir:"*) ;; *) echo "Add to PATH: export PATH=\"$dir:\$PATH\"" ;; esac
