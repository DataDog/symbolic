#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIMIT="${LIMIT:-2000}"
OUTPUT="$SCRIPT_DIR/symbol_files.csv"
# MODE: "largest" (default) selects the biggest files first using the file_size
# index; "random" uses ORDER BY RANDOM() for an unbiased sample.
MODE="${MODE:-largest}"
# Optional: restrict to a specific org_id (leave unset to query all orgs).
ORG_ID="${ORG_ID:-}"
# UNIQUE_FILE_NAME: "normalized" (default) deduplicates by file_name after
# stripping build-ID suffixes (-<digits>.so); "exact" deduplicates by the
# literal file_name; "none" skips deduplication entirely.
UNIQUE_FILE_NAME="${UNIQUE_FILE_NAME:-normalized}"

if [[ "$MODE" == "random" ]]; then
  ORDER_CLAUSE="ORDER BY RANDOM()"
  # For random mode with dedup, fetch extra rows so dedup has enough candidates.
  FETCH_LIMIT="${FETCH_LIMIT:-$((LIMIT * 10))}"
else
  # Fetch more rows than needed so client-side deduplication has enough candidates.
  # DISTINCT ON would require a full-table sort (no index); fetching extra rows and
  # deduplicating in awk uses the existing file_size index and avoids timeouts.
  FETCH_LIMIT="${FETCH_LIMIT:-$((LIMIT * 500))}"
  ORDER_CLAUSE="ORDER BY file_size DESC"
fi

ORG_FILTER=""
[[ -n "$ORG_ID" ]] && ORG_FILTER="AND org_id = ${ORG_ID}"

ORG_DESC="${ORG_ID:+org=$ORG_ID }"
echo "=== Querying staging DB (mode=$MODE unique=$UNIQUE_FILE_NAME ${ORG_DESC}fetch=$FETCH_LIMIT, target=$LIMIT) ==="

RAW="$OUTPUT.raw"
orgstore toolbox psql \
  --orgstore-cluster deobfuscation \
  --datacenter us1.staging.dog \
  -e "COPY (
    SELECT symbol_file_blob_path, file_size, file_name
    FROM elf_symbol_files
    WHERE symbol_source = 'debug_info'
    ${ORG_FILTER}
    ${ORDER_CLAUSE}
    LIMIT ${FETCH_LIMIT}
  ) TO STDOUT WITH (FORMAT CSV, HEADER true)" \
  > "$RAW"

# Extract CSV lines (skip orgstore preamble), optionally deduplicating by
# file_name (col 3).  Three modes:
#   normalized  strip build-ID suffixes (-<digits>.so) before dedup so that
#               libfoo-123.so and libfoo-456.so count as the same file.
#   exact       deduplicate by the literal file_name value.
#   none        no deduplication; take the first LIMIT rows as-is.
awk -F',' -v limit="$LIMIT" -v unique="$UNIQUE_FILE_NAME" '
  /^symbol_file_blob_path/ { print; found=1; next }
  found {
    if (unique == "none") {
      print; if (++count >= limit) exit
    } else {
      key = $3
      if (unique == "normalized") gsub(/-[0-9]+\.so/, ".so", key)
      if (!seen[key]++) { print; if (++count >= limit) exit }
    }
  }
' "$RAW" > "$OUTPUT"
rm -f "$RAW"

ROW_COUNT=$(tail -n +2 "$OUTPUT" | wc -l | tr -d ' ')
echo "=== Done: $ROW_COUNT rows saved to $OUTPUT ==="

