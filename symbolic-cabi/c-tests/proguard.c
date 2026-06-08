#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "symbolic.h"

static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    size_t len = (size_t)ftell(f);
    rewind(f);
    char *buf = malloc(len);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, len, f);
    fclose(f);
    *out_len = len;
    return buf;
}

void test_proguardcache_from_mapping(void) {
    printf("[TEST] proguardcache_from_mapping:\n");

    size_t len = 0;
    char *mapping = read_file("../py/tests/res/proguard.txt", &len);
    assert(mapping != NULL);

    SymbolicProguardCache *cache =
        symbolic_proguardcache_from_mapping((const uint8_t *)mapping, len);
    assert(symbolic_err_get_last_code() == SYMBOLIC_ERROR_CODE_NO_ERROR);
    assert(cache != NULL);
    printf("  cache built ok\n");

    const uint8_t *bytes = symbolic_proguardcache_get_bytes(cache);
    size_t size = symbolic_proguardcache_get_size(cache);
    assert(bytes != NULL);
    assert(size > 0);
    printf("  cache binary size: %zu bytes\n", size);

    symbolic_proguardcache_test(cache);
    assert(symbolic_err_get_last_code() == SYMBOLIC_ERROR_CODE_NO_ERROR);
    printf("  integrity check passed\n");

    free(mapping);
    symbolic_proguardcache_free(cache);
    symbolic_err_clear();
    printf("  PASS\n\n");
}

void test_proguardcache_open_roundtrip(void) {
    printf("[TEST] proguardcache_open (round-trip):\n");

    size_t len = 0;
    char *mapping = read_file("../py/tests/res/proguard.txt", &len);
    assert(mapping != NULL);

    SymbolicProguardCache *built =
        symbolic_proguardcache_from_mapping((const uint8_t *)mapping, len);
    assert(built != NULL);
    free(mapping);

    const uint8_t *bytes = symbolic_proguardcache_get_bytes(built);
    size_t size = symbolic_proguardcache_get_size(built);

    /* copy bytes so we can free 'built' independently */
    uint8_t *copy = malloc(size);
    assert(copy != NULL);
    memcpy(copy, bytes, size);
    symbolic_proguardcache_free(built);

    SymbolicProguardCache *loaded = symbolic_proguardcache_open(copy, size);
    assert(symbolic_err_get_last_code() == SYMBOLIC_ERROR_CODE_NO_ERROR);
    assert(loaded != NULL);
    printf("  re-opened from binary ok\n");

    symbolic_proguardcache_test(loaded);
    assert(symbolic_err_get_last_code() == SYMBOLIC_ERROR_CODE_NO_ERROR);
    printf("  integrity check passed\n");

    free(copy);
    symbolic_proguardcache_free(loaded);
    symbolic_err_clear();
    printf("  PASS\n\n");
}

void test_proguardcache_remap_stacktrace(void) {
    printf("[TEST] proguardcache_remap_stacktrace:\n");

    size_t len = 0;
    char *mapping = read_file("../py/tests/res/proguard.txt", &len);
    assert(mapping != NULL);

    SymbolicProguardCache *cache =
        symbolic_proguardcache_from_mapping((const uint8_t *)mapping, len);
    assert(cache != NULL);
    free(mapping);

    /*
     * io.sentry.sample.MainActivity -> io.sentry.sample.MainActivity:
     *     1:1:void bar():54:54 -> a
     *     1:1:void foo():44   -> a
     *     1:1:void onClickHandler(android.view.View):40 -> a
     *
     * Frame at line 1 expands to three inline frames: bar, foo, onClickHandler.
     */
    const char *input =
        "java.lang.RuntimeException: test\n"
        "    at io.sentry.sample.MainActivity.a(MainActivity.kt:1)\n";

    SymbolicStr input_str = symbolic_str_from_cstr(input);
    SymbolicStr result = symbolic_proguardcache_remap_stacktrace(cache, &input_str);
    assert(symbolic_err_get_last_code() == SYMBOLIC_ERROR_CODE_NO_ERROR);

    printf("  remapped:\n%.*s\n", (int)result.len, result.data);

    assert(memmem(result.data, result.len, "bar", 3) != NULL);
    assert(memmem(result.data, result.len, "foo", 3) != NULL);
    assert(memmem(result.data, result.len, "onClickHandler", 14) != NULL);

    symbolic_str_free(&result);
    symbolic_proguardcache_free(cache);
    symbolic_err_clear();
    printf("  PASS\n\n");
}

int main() {
    test_proguardcache_from_mapping();
    test_proguardcache_open_roundtrip();
    test_proguardcache_remap_stacktrace();

    return 0;
}
