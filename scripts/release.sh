#!/usr/bin/env bash
# build the release archives: zip + tar.gz + tar.xz + SHA256SUMS.
# idempotent: reruns overwrite cleanly.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-1.0.0}"
NAME="rtbf-shredder"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

OUT="release"
mkdir -p "$OUT"
rm -f "$OUT/$NAME-$VERSION".* "$OUT/SHA256SUMS.txt"

# archive the tracked tree (no .git, no caches, no vaults)
git archive --format=tar --prefix="$NAME-$VERSION/" HEAD -o "$STAGE/src.tar"
mkdir -p "$STAGE/zip"
cp "$STAGE/src.tar" "$STAGE/zip/"
(
  cd "$STAGE/zip"
  tar xf src.tar
  rm src.tar
  zip -qr "$STAGE/$NAME-$VERSION.zip" "$NAME-$VERSION"
)
gzip -c "$STAGE/src.tar" > "$OUT/$NAME-$VERSION.tar.gz"
xz -c "$STAGE/src.tar" > "$OUT/$NAME-$VERSION.tar.xz"
cp "$STAGE/$NAME-$VERSION.zip" "$OUT/$NAME-$VERSION.zip"

(
  cd "$OUT"
  sha256sum "$NAME-$VERSION.zip" "$NAME-$VERSION.tar.gz" \
    "$NAME-$VERSION.tar.xz" > SHA256SUMS.txt
)

echo "release $VERSION built:"
python3 - <<PY
import hashlib, pathlib
out = pathlib.Path("$OUT")
for f in ["$NAME-$VERSION.zip", "$NAME-$VERSION.tar.gz",
          "$NAME-$VERSION.tar.xz"]:
    d = hashlib.sha256((out / f).read_bytes()).hexdigest()
    print(f"  {f}  {d[:16]}...  {(out / f).stat().st_size} bytes")
print("  SHA256SUMS.txt")
PY
