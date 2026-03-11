#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIFFS="$SCRIPT_DIR/diffs"

if [[ -z "$(ls -A "$DIFFS"/*.diff 2>/dev/null)" ]]; then
  echo "No .diff files found. Run 03_generate_and_compare.sh first." >&2
  exit 1
fi

# For each added/changed line (">") in the location entries, check that
# the lang: field matches what the file extension implies.
#
# Location line format:
#   >   [N] 0xADDR func:NAME entryPC:0xADDR file:/path/to/file.ext:LINE lang:LANG
#   >     inlined into func:NAME entryPC:0xADDR file:/path/to/file.ext:LINE lang:LANG
#
# Extension → expected language mapping (Unknown = skip, not validated):
#   .c                        → C
#   .cc .cpp .cxx .c++ .C    → C++
#   .hh .hpp .hxx             → C++
#   .rs                       → Rust
#   .go                       → Go
#   .py .pyx                  → Python
#   .m                        → ObjC
#   .mm                       → ObjCpp
#   .swift                    → Swift
#   .java                     → Java
#   .cs                       → CSharp
#   .d                        → D
#   .f .f90 .f95 .for         → Fortran
#   .h                        → skip (ambiguous: C or C++)
#   .s .S .asm                → skip (assembly)

awk '
function ext_to_lang(ext,    e) {
  e = tolower(ext)
  if (e == "c")                                    return "C"
  if (e == "cc" || e == "cpp" || e == "cxx" ||
      e == "c++" || e == "hh" || e == "hpp" ||
      e == "hxx")                                  return "C++"
  if (e == "rs")                                   return "Rust"
  if (e == "go")                                   return "Go"
  if (e == "py" || e == "pyx")                     return "Python"
  if (e == "m")                                    return "ObjC"
  if (e == "mm")                                   return "ObjCpp"
  if (e == "swift")                                return "Swift"
  if (e == "java")                                 return "Java"
  if (e == "cs")                                   return "CSharp"
  if (e == "d")                                    return "D"
  if (e == "f" || e == "f90" || e == "f95" ||
      e == "for")                                  return "Fortran"
  # .h, .s, .S, .asm and anything else → skip
  return ""
}

FNR == 1 { current_file = FILENAME }

# Only inspect lines added/changed in the lto branch ("> " prefix).
/^> / && / file:/ && / lang:/ {
  total++

  # Extract the substring after "file:"
  idx = index($0, " file:")
  rest = substr($0, idx + 6)
  # rest: "/path/to/file.c:161 lang:C  ..."

  # Extract lang value (word after "lang:")
  lang_idx = index(rest, " lang:")
  lang = substr(rest, lang_idx + 6)
  gsub(/[[:space:]].*$/, "", lang)

  # Extract file path (everything before ":LINE")
  filepath_colon_line = substr(rest, 1, lang_idx - 1)
  # Strip the trailing ":LINE" — last colon onwards
  filepath = filepath_colon_line
  sub(/:[0-9]+$/, "", filepath)

  # Get the file extension (after last dot)
  ext = filepath
  sub(/.*\./, "", ext)
  if (ext == filepath) ext = ""  # no dot found

  expected = ext_to_lang(ext)
  if (expected == "") next  # skip ambiguous/unknown extensions

  checked++
  if (lang != expected) {
    mismatches++
    if (mismatches <= 20) {
      printf "MISMATCH [%s]\n  file: %s\n  lang: %s  (expected: %s)\n",
             current_file, filepath_colon_line, lang, expected
    }
  }
}

END {
  printf "\n========================================\n"
  printf "Language check: %d locations checked, %d mismatches\n", checked, mismatches
  printf "========================================\n"
  if (mismatches > 20) {
    printf "(first 20 mismatches shown above; %d more omitted)\n", mismatches - 20
  }
}
' "$DIFFS"/*.diff
