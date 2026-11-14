#!/bin/sh
set -eu

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
  echo 'Passport: this installer provides a binary only for Linux x86_64.' >&2
  exit 1
fi

for command_name in curl tar sha256sum install mktemp mkdir; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Passport: required command not found: $command_name" >&2
    exit 1
  fi
done

release_url="${PASSPORT_RELEASE_URL:-https://github.com/plu-nz/mono.passport/releases/latest/download}"
archive='passport-linux-x86_64.tar.gz'
temp_dir="$(mktemp -d)"
trap 'rm -rf -- "$temp_dir"' EXIT

curl -fsSL "$release_url/$archive" -o "$temp_dir/$archive"
curl -fsSL "$release_url/$archive.sha256" -o "$temp_dir/$archive.sha256"
(cd "$temp_dir" && sha256sum -c "$archive.sha256")
tar -xzf "$temp_dir/$archive" -C "$temp_dir"

extension_archive='passport-extension-chromium.tar.gz'
extension_available=false
if curl -fsSL "$release_url/$extension_archive" -o "$temp_dir/$extension_archive" 2>/dev/null; then
  curl -fsSL "$release_url/$extension_archive.sha256" -o "$temp_dir/$extension_archive.sha256"
  (cd "$temp_dir" && sha256sum -c "$extension_archive.sha256")
  extension_available=true
fi

install_root="${XDG_DATA_HOME:-$HOME/.local/share}"
user_bin="$HOME/.local/bin"
# Passport was called Passage: keep its settings, pairings, extension and
# signing key, and remove the files installed under the old name.
for base in "${XDG_CONFIG_HOME:-$HOME/.config}" "$install_root"; do
  if [ -d "$base/passage" ] && [ ! -e "$base/passport" ]; then
    mv "$base/passage" "$base/passport"
  fi
done
rm -f "$user_bin/passage" "$user_bin/passage-native-host" "$user_bin/passage-install-native-host" \
  "$install_root/applications/nz.plu.passage.desktop" "$install_root/icons/hicolor/512x512/apps/nz.plu.passage.png"
install -Dm755 "$temp_dir/passport" "$user_bin/.passport.new"
mv -f "$user_bin/.passport.new" "$user_bin/passport"
if [ -f "$temp_dir/passport-native-host" ]; then
  install -Dm755 "$temp_dir/passport-native-host" "$user_bin/.passport-native-host.new"
  mv -f "$user_bin/.passport-native-host.new" "$user_bin/passport-native-host"
fi
if [ -f "$temp_dir/install-native-host.sh" ]; then
  install -Dm755 "$temp_dir/install-native-host.sh" "$user_bin/passport-install-native-host"
fi
install -Dm644 "$temp_dir/nz.plu.passport.png" "$install_root/icons/hicolor/512x512/apps/nz.plu.passport.png"
# Releases from 0.5 ship every icon size and the symbolic icon.
if [ -d "$temp_dir/icons" ]; then
  for size in 16 24 32 48 64 128 256 512; do
    install -Dm644 "$temp_dir/icons/hicolor/$size.png" "$install_root/icons/hicolor/${size}x${size}/apps/nz.plu.passport.png"
  done
  install -Dm644 "$temp_dir/icons/icon.svg" "$install_root/icons/hicolor/scalable/apps/nz.plu.passport.svg"
  install -Dm644 "$temp_dir/icons/icon-symbolic.svg" "$install_root/icons/hicolor/symbolic/apps/nz.plu.passport-symbolic.svg"
  if command -v gtk-update-icon-cache >/dev/null 2>&1; then gtk-update-icon-cache -q -t "$install_root/icons/hicolor" || true; fi
fi
install -Dm644 "$temp_dir/nz.plu.passport.desktop" "$install_root/applications/nz.plu.passport.desktop"
if [ "$extension_available" = true ]; then
  extension_dir="$install_root/passport/extension-chromium"
  mkdir -p "$extension_dir"
  tar -xzf "$temp_dir/$extension_archive" -C "$extension_dir"
  printf 'Extension unpacked to %s; load this folder in Brave or Chrome and register the IDs with the connector.\n' "$extension_dir"
fi

host_registered=false
if [ -f "$temp_dir/passport-native-host" ] && [ -f "$temp_dir/install-native-host.sh" ]; then
  default_id=''
  if [ "$extension_available" = true ] && [ -f "$temp_dir/extension-id.txt" ]; then
    IFS= read -r default_id < "$temp_dir/extension-id.txt"
  fi
  brave_id="${PASSPORT_BRAVE_EXTENSION_ID:-$default_id}"
  chrome_id="${PASSPORT_CHROME_EXTENSION_ID:-$default_id}"
  if [ -n "$brave_id" ] && [ -n "$chrome_id" ]; then
    "$temp_dir/install-native-host.sh" "$user_bin/passport-native-host" "$brave_id" "$chrome_id"
    host_registered=true
  fi
fi

printf 'Passport installed at %s\n' "$user_bin/passport"

# Passport drives GNU pass, GnuPG and Git; it installs without them but cannot open a vault.
missing=''
for dependency in pass gpg git; do
  command -v "$dependency" >/dev/null 2>&1 || missing="$missing $dependency"
done
if [ -n "$missing" ]; then
  printf 'Passport also needs:%s. Install them with:\n' "$missing"
  if command -v pacman >/dev/null 2>&1; then
    printf '  sudo pacman -S --needed pass gnupg git\n'
  elif command -v apt-get >/dev/null 2>&1; then
    printf '  sudo apt install pass gnupg git\n'
  elif command -v dnf >/dev/null 2>&1; then
    printf '  sudo dnf install pass gnupg2 git\n'
  elif command -v zypper >/dev/null 2>&1; then
    printf '  sudo zypper install password-store gpg2 git\n'
  else
    printf '  your package manager (GNU pass, GnuPG and Git)\n'
  fi
fi
if [ -f "$temp_dir/passport-native-host" ] && [ "$host_registered" = false ]; then
  printf 'Connector installed. To register Brave and Chrome, run: %s/passport-install-native-host %s/passport-native-host ID_BRAVE ID_CHROME\n' "$user_bin" "$user_bin"
fi
