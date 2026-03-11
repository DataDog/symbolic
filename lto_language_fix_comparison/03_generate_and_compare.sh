#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUFFIX="${SUFFIX:-}"
DOWNLOADS="$SCRIPT_DIR/downloads${SUFFIX}"
DIFFS="$SCRIPT_DIR/diffs${SUFFIX}"
BIN_LTO="$SCRIPT_DIR/bin/symcache_debug_lto"
BIN_MASTER="$SCRIPT_DIR/bin/symcache_debug_master"
PRINT_SYMCACHE="${PRINT_SYMCACHE:-$HOME/dd/dd-go/print_symcache}"
CSV="$SCRIPT_DIR/symbol_files${SUFFIX}.csv"
FAILURES="$SCRIPT_DIR/generate_failures${SUFFIX}.txt"
PREVIEW_COUNT="${PREVIEW_COUNT:-3}"
PARALLEL="${PARALLEL:-8}"

for bin in "$BIN_LTO" "$BIN_MASTER"; do
  if [[ ! -x "$bin" ]]; then
    echo "ERROR: $bin not found or not executable. Run 00_build.sh first." >&2
    exit 1
  fi
done

if [[ ! -x "$PRINT_SYMCACHE" ]]; then
  echo "ERROR: $PRINT_SYMCACHE not found or not executable." >&2
  echo "  Set PRINT_SYMCACHE=/path/to/print_symcache to override." >&2
  exit 1
fi

if [[ ! -d "$DOWNLOADS" ]] || [[ -z "$(ls -A "$DOWNLOADS" 2>/dev/null)" ]]; then
  echo "ERROR: $DOWNLOADS is empty. Run 02_download.sh first." >&2
  exit 1
fi

mkdir -p "$DIFFS"
> "$FAILURES"

mapfile -t ELF_FILES < <(find "$DOWNLOADS" -maxdepth 1 -type f)
TOTAL="${#ELF_FILES[@]}"

echo "=== Processing $TOTAL files (parallel=$PARALLEL) ==="

# Progress tracking: workers write one line per completed file to a named pipe;
# a background reader updates the progress bar (no flock/locking needed).
PROGRESS_FIFO="$(mktemp -u)"
mkfifo "$PROGRESS_FIFO"

(
  count=0
  while IFS= read -r _; do
    count=$((count + 1))
    filled=$((count * 40 / TOTAL))
    bar="$(printf '%*s' "$filled"        '' | tr ' ' '#')\
$(printf '%*s' "$((40 - filled))" '' | tr ' ' '-')"
    printf '\r  [%s] %d/%d (%d%%)' "$bar" "$count" "$TOTAL" "$((count * 100 / TOTAL))" >&2
  done < "$PROGRESS_FIFO"
) &
PROGRESS_PID=$!

# Keep a write fd open so the reader only gets EOF when we explicitly close it.
exec 3>"$PROGRESS_FIFO"

process_one() {
  local elf="$1"
  local name
  name="$(basename "$elf")"
  local diff_file="$DIFFS/${name}.diff"
  local nodiff_file="$DIFFS/${name}.nodiff"
  local lang_check_file="$DIFFS/${name}.lang_check"

  # Resume: skip already processed files.
  if [[ -f "$diff_file" ]] || [[ -f "$nodiff_file" ]]; then
    _progress_tick
    return 0
  fi

  local tmp_lto tmp_master tmp_lto_txt tmp_master_txt
  tmp_lto="$(mktemp)"
  tmp_master="$(mktemp)"
  tmp_lto_txt="$(mktemp)"
  tmp_master_txt="$(mktemp)"

  local ok=1

  if ! "$BIN_LTO" -d "$elf" -w -c "$tmp_lto" &>/dev/null; then
    echo "  FAIL (lto): $name" | tee -a "$FAILURES"
    ok=0
  fi

  if ! "$BIN_MASTER" -d "$elf" -w -c "$tmp_master" &>/dev/null; then
    echo "  FAIL (master): $name" | tee -a "$FAILURES"
    ok=0
  fi

  if [[ "$ok" -eq 1 ]]; then
    if cmp -s "$tmp_lto" "$tmp_master"; then
      # Binary-identical: no need to run print_symcache at all.
      touch "$nodiff_file"
    else
      # Binaries differ: produce a human-readable diff via print_symcache.
      "$PRINT_SYMCACHE" "$tmp_lto"    > "$tmp_lto_txt"    2>/dev/null || true
      "$PRINT_SYMCACHE" "$tmp_master" > "$tmp_master_txt" 2>/dev/null || true

      local tmp_diff
      tmp_diff="$(mktemp)"
      if diff -u "$tmp_master_txt" "$tmp_lto_txt" > "$tmp_diff"; then
        # print_symcache output is identical despite binary difference.
        rm -f "$tmp_diff"
        touch "$nodiff_file"
      else
        # Prepend file_name header then the diff.
        local file_name
        file_name="$(awk -F',' 'NR>1 { blob=$1; gsub("/","_",blob); if (blob==name) { print $3; exit } }' \
          name="$name" "$CSV")"
        { echo "file_name: $file_name"; cat "$tmp_diff"; } > "$diff_file"
        "$PRINT_SYMCACHE" --check-language "$tmp_lto" > "$tmp_diff"
        if ! grep -q "^0 mismatches" "$tmp_diff"; then
          { echo "file_name: $file_name"; cat "$tmp_diff"; } > "$lang_check_file"
        fi
        rm -f "$tmp_diff"
      fi
      # diff_file kept only when non-empty (outputs differ)
    fi
  fi

  rm -f "$tmp_lto" "$tmp_master" "$tmp_lto_txt" "$tmp_master_txt"
  _progress_tick
}

_progress_tick() {
  # A single short write to a pipe is atomic (POSIX guarantees atomicity for
  # writes <= PIPE_BUF, which is at least 512 bytes on all platforms).
  printf 'x\n' >> "$PROGRESS_FIFO"
}

export -f process_one _progress_tick
export BIN_LTO BIN_MASTER PRINT_SYMCACHE DIFFS FAILURES CSV PROGRESS_FIFO TOTAL

printf '%s\n' "${ELF_FILES[@]}" \
  | xargs -P "$PARALLEL" -I{} bash -c 'process_one "$@"' _ {}

exec 3>&-          # close write end -> reader sees EOF and exits
wait "$PROGRESS_PID"
printf '\n' >&2
rm -f "$PROGRESS_FIFO"

# Summary
FAIL_COUNT=$(wc -l < "$FAILURES" | tr -d ' ')
DIFF_COUNT=$(find "$DIFFS" -name "*.diff" 2>/dev/null | wc -l | tr -d ' ')
NODIFF_COUNT=$(find "$DIFFS" -name "*.nodiff" 2>/dev/null | wc -l | tr -d ' ')

echo ""
echo "========================================"
echo "Summary: $DIFF_COUNT / $((DIFF_COUNT + NODIFF_COUNT)) files differ  ($FAIL_COUNT failures)"
echo "========================================"

if [[ "$DIFF_COUNT" -gt 0 ]]; then
  echo ""
  echo "Differing files:"
  find "$DIFFS" -name "*.diff" | sort | sed 's|.*/||; s|\.diff$||' | sed 's/^/  /'

  echo ""
  echo "=== Preview of first $PREVIEW_COUNT diffs ==="
  SHOWN=0
  while IFS= read -r diff_file && [[ "$SHOWN" -lt "$PREVIEW_COUNT" ]]; do
    name="$(basename "$diff_file" .diff)"
    echo ""
    echo "--- $name ---"
    head -50 "$diff_file"
    SHOWN=$((SHOWN + 1))
  done < <(find "$DIFFS" -name "*.diff" | sort)
fi

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  echo ""
  echo "Failures logged to: $FAILURES"
fi
