/* No Windows SDK/runtime needed. Real PE/PDB fixtures for conversion tests. */
volatile int observed;
__declspec(noinline) int crash_frame(int n) {
    volatile int values[12];
    values[0] = n;
    values[11] = n + 1;
    observed = values[0] + values[11];
    return observed;
}
__declspec(noinline) int caller_frame(int n) {
    volatile int values[8];
    values[0] = n;
    return crash_frame(values[0]) + values[0];
}
void entry(void) { observed = caller_frame(42); }
