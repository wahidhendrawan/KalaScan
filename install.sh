#!/bin/sh
# Install the latest KalaScan release binary.
#   curl -fsSL https://raw.githubusercontent.com/wahidhendrawan/KalaScan/main/install.sh | sh
# Override the destination with KALASCAN_INSTALL_DIR=/some/bin
set -eu

repo="wahidhendrawan/KalaScan"
dir="${KALASCAN_INSTALL_DIR:-/usr/local/bin}"

case "$(uname -s)" in
  Darwin) target=universal-apple-darwin ;;
  Linux)
    case "$(uname -m)" in
      x86_64) target=x86_64-unknown-linux-gnu ;;
      aarch64 | arm64) target=aarch64-unknown-linux-gnu ;;
      *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
    esac
    ;;
  *) echo "unsupported OS: $(uname -s) (build from source with 'cargo build --release')" >&2; exit 1 ;;
esac

asset="kalascan-$target.tar.gz"
base="https://github.com/$repo/releases/latest/download"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "downloading $base/$asset"
curl -fsSL "$base/$asset" -o "$tmp/$asset"
# The release publishes kalascan-<target>.sha256, listing the .tar.gz.
curl -fsSL "$base/kalascan-$target.sha256" -o "$tmp/sum"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$tmp" && sha256sum -c sum >/dev/null)
elif command -v shasum >/dev/null 2>&1; then
  (cd "$tmp" && shasum -a 256 -c sum >/dev/null)
else
  echo "need sha256sum or shasum to verify the download" >&2; exit 1
fi

tar -xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$dir" 2>/dev/null || true
install -m 0755 "$tmp/kalascan" "$dir/kalascan" 2>/dev/null ||
  { mv "$tmp/kalascan" "$dir/kalascan" && chmod 0755 "$dir/kalascan"; }

echo "installed $("$dir/kalascan" --version) to $dir/kalascan"
