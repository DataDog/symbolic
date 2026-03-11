#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="/Users/nicolas.savoire/dd/symbolic"

echo "=== Building symcache_debug from nsavoire/lto_language ==="
cd "$REPO"
cargo build --package symcache_debug --release
cp target/release/symcache_debug "$SCRIPT_DIR/bin/symcache_debug_lto"
echo "  -> copied to bin/symcache_debug_lto"

echo ""
echo "=== Building symcache_debug from dd_master ==="
cd "$REPO"
ORIGINAL_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
echo "  (current branch: $ORIGINAL_BRANCH)"

git checkout dd_master
cargo build --package symcache_debug --release
cp target/release/symcache_debug "$SCRIPT_DIR/bin/symcache_debug_master"
echo "  -> copied to bin/symcache_debug_master"

echo ""
echo "=== Restoring branch $ORIGINAL_BRANCH in $REPO ==="
git checkout "$ORIGINAL_BRANCH"

echo ""
echo "=== Done ==="
ls -lh "$SCRIPT_DIR/bin/"
