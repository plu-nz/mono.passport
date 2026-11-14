#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_root="${XDG_DATA_HOME:-$HOME/.local/share}"
user_bin="${HOME}/.local/bin"
build_tmp="${XDG_CACHE_HOME:-$HOME/.cache}/passport-go-tmp"
mkdir -p "$build_tmp"

# Passport was called Passage: keep its settings, pairings, extension and
# signing key, and remove the files installed under the old name.
for base in "${XDG_CONFIG_HOME:-$HOME/.config}" "$install_root"; do
  if [ -d "$base/passage" ] && [ ! -e "$base/passport" ]; then
    mv "$base/passage" "$base/passport"
  fi
done
rm -f "$user_bin/passage" "$user_bin/passage-native-host" "$user_bin/passage-install-native-host" \
  "$install_root/applications/nz.plu.passage.desktop" "$install_root/icons/hicolor/512x512/apps/nz.plu.passage.png"
export GOTMPDIR="$build_tmp" TMPDIR="$build_tmp"

cd "$repo_dir"
pnpm install --frozen-lockfile
pnpm --filter @passport/desktop build
pnpm build:extension
go build -o desktop/build/passport ./desktop
go build -o native-host/build/passport-native-host ./native-host

install -Dm755 desktop/build/passport "$user_bin/passport"
install -Dm755 native-host/build/passport-native-host "$user_bin/passport-native-host"
install -Dm755 scripts/install-native-host.sh "$user_bin/passport-install-native-host"
extension_dir="$install_root/passport/extension-chromium"
mkdir -p "$extension_dir"
cp -a extension/.output/chrome-mv3/. "$extension_dir/"
extension_id="$(python3 - <<'PY'
import base64
import hashlib
import json
from pathlib import Path
identity = json.loads(Path('extension/identity.json').read_text(encoding='utf-8'))
manifest = json.loads(Path('extension/.output/chrome-mv3/manifest.json').read_text(encoding='utf-8'))
if manifest.get('key') != identity['key']:
    raise SystemExit('Extension key does not match the configured ID')
digest = hashlib.sha256(base64.b64decode(identity['key'], validate=True)).digest()
extension_id = ''.join(chr(97 + nibble) for byte in digest[:16] for nibble in (byte >> 4, byte & 15))
if extension_id != identity['id']:
    raise SystemExit('Invalid extension ID')
print(extension_id)
PY
)"
"$user_bin/passport-install-native-host" "$user_bin/passport-native-host" "$extension_id" "$extension_id"
install -Dm644 desktop/icons/icon.png "$install_root/icons/hicolor/512x512/apps/nz.plu.passport.png"
install -Dm644 scripts/nz.plu.passport.desktop "$install_root/applications/nz.plu.passport.desktop"

printf 'Passport installed at %s\n' "$user_bin/passport"
printf 'Extension installed at %s; load this folder in Brave and Chrome and approve each pairing.\n' "$extension_dir"
