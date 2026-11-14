#!/usr/bin/env bash
# Renders the Passport icon (desktop/icons/icon.svg) to the PNG sizes the
# desktop installs and to the website favicons. Run after changing the SVG and
# commit the results; builds and CI do not need rsvg-convert or ImageMagick.
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
icons="$repo_dir/desktop/icons"
mkdir -p "$icons/hicolor" "$repo_dir/web/icons"
for size in 16 24 32 48 64 128 256 512; do
  rsvg-convert -w "$size" -h "$size" "$icons/icon.svg" -o "$icons/hicolor/$size.png"
done
cp "$icons/hicolor/512.png" "$icons/icon.png"
cp "$icons/icon.svg" "$repo_dir/web/icons/favicon.svg"
rsvg-convert -w 180 -h 180 "$icons/icon.svg" -o "$repo_dir/web/icons/apple-touch-icon.png"
magick "$icons/hicolor/16.png" "$icons/hicolor/32.png" "$icons/hicolor/48.png" "$repo_dir/web/icons/favicon.ico"
