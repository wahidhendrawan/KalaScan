#!/bin/sh
# Install the latest KalaScan release binary.
#   curl -fsSL https://raw.githubusercontent.com/wahidhendrawan/KalaScan/main/install.sh | sh
# Override the destination with KALASCAN_INSTALL_DIR=/some/bin
set -eu

repo="wahidhendrawan/KalaScan"
dir="${KALASCAN_INSTALL_DIR:-/usr/local/bin}"

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
url="https://github.com/$repo/releases/latest/download/$asset"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "downloading $url"
curl -fsSL "$url" -o "$tmp/$asset"
if command -v sha256sum >/dev/null 2>&1; then
  curl -fsSL "$url.sha256" -o "$tmp/$asset.sha256"
  (cd "$tmp" && sha256sum -c "$asset.sha256" >/dev/null)
elif command -v shasum >/dev/null 2>&1; then
  curl -fsSL "$url.sha256" -o "$tmp/$asset.sha256"
  (cd "$tmp" && shasum -a 256 -c "$asset.sha256" >/dev/null)
fi

tar -xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$dir" 2>/dev/null || true
install -m 0755 "$tmp/kalascan" "$dir/kalascan" 2>/dev/null ||
  { mv "$tmp/kalascan" "$dir/kalascan" && chmod 0755 "$dir/kalascan"; }

echo "installed $("$dir/kalascan" --version) to $dir/kalascan"
