#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Re-exec under aws-vault if not already running with AWS credentials.
if [[ -z "${AWS_ACCESS_KEY_ID:-}" ]]; then
  exec aws-vault exec sso-staging-engineering -- "$0" "$@"
fi
CSV="$SCRIPT_DIR/symbol_files.csv"
DOWNLOADS="$SCRIPT_DIR/downloads"
FAILURES="$SCRIPT_DIR/download_failures.txt"
S3_BUCKET="s3://error-tracking-srcmap-staging"
PARALLEL="${PARALLEL:-8}"

if [[ ! -f "$CSV" ]]; then
  echo "ERROR: $CSV not found. Run 01_query_db.sh first." >&2
  exit 1
fi

mkdir -p "$DOWNLOADS"

# Build list of blob paths — skip the orgstore preamble by anchoring on the CSV header.
mapfile -t BLOB_PATHS < <(awk '/^symbol_file_blob_path/{found=1; next} found' "$CSV" | cut -d',' -f1)

echo "=== Downloading ${#BLOB_PATHS[@]} files (parallel=$PARALLEL) ==="

download_one() {
  local blob_path="$1"
  local filename
  filename="$(echo "$blob_path" | tr '/' '_')"
  local dest="$DOWNLOADS/$filename"

  if [[ -f "$dest" ]]; then
    echo "  SKIP (exists): $filename"
    return 0
  fi

  if aws s3 cp "${S3_BUCKET}/${blob_path}" "$dest" --quiet 2>/dev/null; then
    echo "  OK: $filename"
  else
    echo "  FAIL: $blob_path" | tee -a "$FAILURES"
    rm -f "$dest"
  fi
}

export -f download_one
export DOWNLOADS S3_BUCKET FAILURES

printf '%s\n' "${BLOB_PATHS[@]}" \
  | xargs -P "$PARALLEL" -I{} bash -c 'download_one "$@"' _ {}

FAIL_COUNT=$(wc -l < "$FAILURES" | tr -d ' ')
DOWNLOADED=$(ls "$DOWNLOADS" | wc -l | tr -d ' ')

echo ""
echo "=== Done: $DOWNLOADED files in downloads/, $FAIL_COUNT failures ==="
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  echo "Failed paths logged to: $FAILURES"
fi
