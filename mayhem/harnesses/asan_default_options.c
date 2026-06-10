/*
 * Weak __asan_default_options baked into every wamr fuzz target.
 *
 * Mayhem owns the RUNTIME ASAN_OPTIONS (abort_on_error=1, symbolize=0, ...) and a Mayhemfile env
 * value would REPLACE that whole set — so we must NOT set ASAN_OPTIONS in the Mayhemfile. The one
 * knob we want regardless — detect_leaks=0 — belongs in a WEAK __asan_default_options compiled into
 * the binary: Mayhem's runtime ASAN_OPTIONS does not override these, and the `weak` attribute lets a
 * real ASAN_OPTIONS still win if someone sets one for local debugging.
 *
 * Why: the wasm loader/validator bails out on the first malformed byte; on some early-reject paths a
 * partially-built module/runtime can hold an allocation that LSan would report at exit. Those are
 * shutdown-ordering leaks in the harness loop, not the memory-safety bugs we care about, and at
 * campaign scale they would flood the queue. ASan/UBSan stay fully on.
 */
const char *
__asan_default_options(void)
{
    return "detect_leaks=0";
}
