#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "symbolic.h"

static uint8_t *read_file(const char *path, size_t *out_len) {
  FILE *file = fopen(path, "rb");
  assert(file != NULL);
  assert(fseek(file, 0, SEEK_END) == 0);
  long size = ftell(file);
  assert(size > 0);
  rewind(file);

  uint8_t *bytes = malloc((size_t)size);
  assert(bytes != NULL);
  assert(fread(bytes, 1, (size_t)size, file) == (size_t)size);
  fclose(file);
  *out_len = (size_t)size;
  return bytes;
}

static int contains(const SymbolicStr *string, const char *needle) {
  size_t needle_len = strlen(needle);
  if (needle_len > string->len) {
    return 0;
  }
  for (size_t index = 0; index <= string->len - needle_len; index++) {
    if (memcmp(string->data + index, needle, needle_len) == 0) {
      return 1;
    }
  }
  return 0;
}

static void test_inspect(const uint8_t *dump, size_t dump_len) {
  printf("[TEST] minidump inspect:\n");
  symbolic_err_clear();
  SymbolicStr result = symbolic_minidump_inspect(dump, dump_len);
  assert(symbolic_err_get_last_code() == SYMBOLIC_ERROR_CODE_NO_ERROR);
  assert(result.data != NULL);
  assert(result.len > 0);
  assert(contains(&result, "\"modules\""));
  assert(contains(&result, "\"os\""));
  symbolic_str_free(&result);
  printf("  PASS\n\n");
}

static void test_process_without_symbols(const uint8_t *dump, size_t dump_len) {
  printf("[TEST] minidump process without symbols:\n");
  symbolic_err_clear();
  SymbolicStr result = symbolic_minidump_process(dump, dump_len, NULL, 0);
  assert(symbolic_err_get_last_code() == SYMBOLIC_ERROR_CODE_NO_ERROR);
  assert(result.data != NULL);
  assert(result.len > 0);
  assert(contains(&result, "\"status\":\"OK\""));
  assert(contains(&result, "\"threads\""));
  symbolic_str_free(&result);
  printf("  PASS\n\n");
}

static void test_invalid_inputs(const uint8_t *dump, size_t dump_len) {
  printf("[TEST] minidump invalid input classification:\n");
  symbolic_err_clear();
  SymbolicStr result = symbolic_minidump_inspect(NULL, 0);
  assert(result.data == NULL);
  assert(symbolic_err_get_last_code() ==
         SYMBOLIC_ERROR_CODE_MINIDUMP_INVALID_ARGUMENT);

  symbolic_err_clear();
  const uint8_t invalid_symcache[] = "not a symcache";
  SymbolicMinidumpSymCache symcache = {
      .contents = invalid_symcache,
      .contents_len = sizeof(invalid_symcache) - 1,
  };
  result = symbolic_minidump_process(dump, dump_len, &symcache, 1);
  assert(result.data == NULL);
  assert(symbolic_err_get_last_code() ==
         SYMBOLIC_ERROR_CODE_MINIDUMP_INVALID_SYMBOLS);
  symbolic_err_clear();
  printf("  PASS\n\n");
}

int main(void) {
  size_t dump_len = 0;
  uint8_t *dump = read_file("../py/tests/res/minidump/crash_linux.dmp",
                            &dump_len);
  test_inspect(dump, dump_len);
  test_process_without_symbols(dump, dump_len);
  test_invalid_inputs(dump, dump_len);
  free(dump);
  return 0;
}
