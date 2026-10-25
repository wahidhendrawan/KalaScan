#!/bin/sh
# Install the latest KalaScan release binary.
#   curl -fsSL https://raw.githubusercontent.com/wahidhendrawan/KalaScan/main/install.sh | sh
# Override the destination with KALASCAN_INSTALL_DIR=/some/bin
set -eu

repo="wahidhendrawan/KalaScan"
dir="${KALASCAN_INSTALL_DIR:-/usr/local/bin}"
# The repository is private, so a token is required to download assets.
# Any token with `repo`/`contents:read` works, e.g. `gh auth token`.
token="${KALASCAN_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"
if [ -z "$token" ] && command -v gh >/dev/null 2>&1; then
  token=$(gh auth token 2>/dev/null || true)
fi
if [ -z "$token" ]; then
  echo "KALASCAN_GITHUB_TOKEN (or GITHUB_TOKEN) is required: the release repo is private." >&2
  exit 1
fi

os=$(uname -s)
arch=$(uname -m)

case "$os" in
  Linux) os_part=x86_64-unknown-linux-gnu ;;
  Darwin) os_part=universal-apple-darwin ;;
  *) echo "unsupported OS: $os (use 'cargo install --path .' instead)" >&2; exit 1 ;;
esac

if [ "$os" = "Linux" ]; then
  case "$arch" in
    x86_64) os_part=x86_64-unknown-linux-gnu ;;
    aarch64 | arm64) os_part=aarch64-unknown-linux-gnu ;;
    *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
  esac
fi

asset="kalascan-$os_part.tar.gz"

# Resolve the asset API URLs from the release manifest. The plain
# releases/latest/download endpoint and browser_download_url both 404
# for private repositories, so we fetch the asset endpoint directly.
api="https://api.github.com/repos/$repo/releases/latest"
manifest=$(curl -fsSL -H "Authorization: Bearer $token" \
  -H "Accept: application/vnd.github+json" "$api")
asset_url() {
  printf '%s' "$manifest" | awk -v want="$1" '
    /"url": *"https:\/\/api\.github\.com\/.*\/assets\/[0-9]+"/ {
      u=$0; sub(/.*"url": *"/,"",u); sub(/".*/,"",u)
    }
    index($0, "\"name\": \"" want "\"") { print u; exit }
  '
}
url=$(asset_url "$asset")
sha_url=$(asset_url "$asset.sha256")
[ -n "$url" ] || { echo "asset $asset not found in the latest release" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "downloading $url"
curl -fsSL -H "Authorization: Bearer $token" \
  -H "Accept: application/octet-stream" "$url" -o "$tmp/$asset"
if [ -n "$sha_url" ]; then
  curl -fsSL -H "Authorization: Bearer $token" \
    -H "Accept: application/octet-stream" "$sha_url" -o "$tmp/$asset.sha256"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmp" && sha256sum -c "$asset.sha256" >/dev/null)
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$tmp" && shasum -a 256 -c "$asset.sha256" >/dev/null)
  fi
fi

tar -xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$dir" 2>/dev/null || true
install -m 0755 "$tmp/kalascan" "$dir/kalascan" 2>/dev/null ||
  { mv "$tmp/kalascan" "$dir/kalascan" && chmod 0755 "$dir/kalascan"; }

echo "installed $("$dir/kalascan" --version) to $dir/kalascan"
