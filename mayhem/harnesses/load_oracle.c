/*
 * load_oracle.c — a small self-contained GOLDEN oracle for WAMR's .wasm loader.
 *
 * wamr has no compact, self-contained pass/fail suite we can run at build time (its real test
 * coverage is the external WebAssembly spec-test suite + sample apps that need a wasi sysroot and a
 * toolchain to compile). So we build a focused golden oracle that pins the loader's accept/reject
 * contract — the exact surface the fuzzer attacks:
 *
 *   1. ACCEPT  — a hand-built, byte-correct minimal module (one exported function `f` that returns
 *                i32 42) must load AND instantiate AND run, returning 42.
 *   2. REJECT  — a buffer whose magic number is corrupted must be REJECTED by wasm_runtime_load
 *                (returns NULL) rather than loaded.
 *   3. REJECT  — a truncated copy of the good module must also be rejected, not loaded.
 *
 * This is a real behavioural oracle: a no-op / "return success" patch to the loader fails case 2/3
 * (it would accept garbage), and a patch that breaks decoding fails case 1. Each check prints a
 * `RESULT <name> PASS|FAIL` line; test.sh parses those into CTRF. It links the same instrumented
 * libiwasm.a built by build.sh, so the oracle runs under ASan/UBSan too.
 */
#include "wasm_export.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* A minimal, valid wasm module:
 *   (module (func (export "f") (result i32) i32.const 42))
 * Hand-assembled binary (verified to load+run by WAMR). */
static const uint8_t good_module[] = {
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, /* "\0asm" + version 1 */
    /* type section: 1 type, () -> (i32) */
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
    /* function section: 1 func, type 0 */
    0x03, 0x02, 0x01, 0x00,
    /* export section: 1 export "f" -> func 0 */
    0x07, 0x05, 0x01, 0x01, 0x66, 0x00, 0x00,
    /* code section: 1 body: i32.const 42; end */
    0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b,
};

#define ERR_SZ 128

static int pass_count = 0;
static int fail_count = 0;

static void
record(const char *name, int ok)
{
    printf("RESULT %s %s\n", name, ok ? "PASS" : "FAIL");
    if (ok)
        pass_count++;
    else
        fail_count++;
}

int
main(void)
{
    char err[ERR_SZ];

    /* ---- case 1: ACCEPT + instantiate + run a byte-correct module ---- */
    {
        wasm_runtime_init();
        uint8_t buf[sizeof(good_module)];
        memcpy(buf, good_module, sizeof(good_module));
        err[0] = 0;
        wasm_module_t mod =
            wasm_runtime_load(buf, sizeof(buf), err, ERR_SZ - 8);
        int ok = 0;
        if (mod) {
            wasm_module_inst_t inst = wasm_runtime_instantiate(
                mod, 64 * 1024, 64 * 1024, err, ERR_SZ - 8);
            if (inst) {
                wasm_function_inst_t f =
                    wasm_runtime_lookup_function(inst, "f");
                wasm_exec_env_t env =
                    wasm_runtime_create_exec_env(inst, 64 * 1024);
                uint32_t argv[1] = { 0 };
                if (f && env
                    && wasm_runtime_call_wasm(env, f, 0, argv)) {
                    ok = (argv[0] == 42);
                }
                if (env)
                    wasm_runtime_destroy_exec_env(env);
                wasm_runtime_deinstantiate(inst);
            }
            else {
                printf("  [instantiate] %s\n", err);
            }
            wasm_runtime_unload(mod);
        }
        else {
            printf("  [load] %s\n", err);
        }
        wasm_runtime_destroy();
        record("accept_good_module_returns_42", ok);
    }

    /* ---- case 2: REJECT a module with a corrupted magic number ---- */
    {
        wasm_runtime_init();
        uint8_t buf[sizeof(good_module)];
        memcpy(buf, good_module, sizeof(good_module));
        buf[0] ^= 0xff; /* break the "\0asm" magic */
        err[0] = 0;
        wasm_module_t mod =
            wasm_runtime_load(buf, sizeof(buf), err, ERR_SZ - 8);
        int rejected = (mod == NULL);
        if (mod)
            wasm_runtime_unload(mod);
        wasm_runtime_destroy();
        record("reject_corrupt_magic", rejected);
    }

    /* ---- case 3: REJECT a truncated module ---- */
    {
        wasm_runtime_init();
        uint8_t buf[sizeof(good_module)];
        memcpy(buf, good_module, sizeof(good_module));
        err[0] = 0;
        /* feed only the first 12 bytes: header + a partial type section */
        wasm_module_t mod = wasm_runtime_load(buf, 12, err, ERR_SZ - 8);
        int rejected = (mod == NULL);
        if (mod)
            wasm_runtime_unload(mod);
        wasm_runtime_destroy();
        record("reject_truncated_module", rejected);
    }

    printf("ORACLE passed=%d failed=%d\n", pass_count, fail_count);
    return fail_count == 0 ? 0 : 1;
}
