#!/usr/bin/env bash
#
# wamr/mayhem/build.sh — build WebAssembly Micro Runtime fuzz harnesses as sanitized
# libFuzzer targets (+ standalone reproducers).
#
# Fuzzed surface: WAMR's .wasm BYTECODE PARSER / LOADER, interpreter, LLVM JIT, and AOT compiler.
# All four OSS-Fuzz harness variants are built:
#   wamr_fuzz_classic_interp  — wasm_mutator_fuzz.cc, WAMR_BUILD_FAST_INTERP=0 (no LLVM)
#   wamr_fuzz_fast_interp     — wasm_mutator_fuzz.cc, WAMR_BUILD_FAST_INTERP=1 (no LLVM)
#   wamr_fuzz_llvm_jit        — wasm_mutator_fuzz.cc, WAMR_BUILD_JIT=1 (needs LLVM)
#   wamr_fuzz_aot_compiler    — aot_compiler_fuzz.cc, AOT path (needs LLVM)
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN). vmlib is compiled WITH $SANITIZER_FLAGS so the parser/loader/interpreter
# (not just the harness) is instrumented.
#
# LLVM dependency: llvm-19-dev is installed in the Dockerfile (baked into the image at build time);
# build.sh can use it offline at the PATCH tier. LLVM_DIR=/usr/lib/llvm-19/lib/cmake/llvm.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"

# BENIGN-UB RELAX (rule 8): WAMR bump-allocates a WASMTableInstance at an offset that is not
# 8-byte aligned, so UBSan's `alignment` sub-check (member access within misaligned address) fires
# on EVERY module that declares a table — ~26 of 40 valid sample modules, i.e. it floods almost
# every non-trivial input and would mask the parser/loader bugs we actually want. We drop ONLY the
# alignment sub-check; ASan and the rest of UBSan (OOB, integer overflow, function-type-mismatch,
# etc.) stay fully active. We append rather than edit SANITIZER_FLAGS so an explicit empty
# --build-arg (no sanitizers) is still honoured.
if printf '%s' "${SANITIZER_FLAGS:-}" | grep -q 'fsanitize=.*\(address\|undefined\)'; then
  SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=alignment"
fi
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${OUT:=/mayhem}"
: "${MAYHEM_JOBS:=$(nproc)}"

# LLVM JIT: ASan is not compatible with LLVM's ORC JIT (JIT-emitted code bypasses ASan's shadow
# mapping). We strip -fsanitize=address for the JIT/AOT variants, keeping UBSan. This mirrors the
# OSS-Fuzz wamr build. SANITIZER_FLAGS_NOSAN_ADDR is derived for those variants by replacing
# "-fsanitize=address,undefined" with "-fsanitize=undefined" (and similar patterns).
SANITIZER_FLAGS_NOSAN_ADDR="$(printf '%s' "$SANITIZER_FLAGS" | \
  sed 's/-fsanitize=address,\([a-z,]*\)/-fsanitize=\1/g; s/-fsanitize=address\b//g')"

# llvm-19-dev (baked into the image) provides LLVMConfig.cmake here:
LLVM_DIR=/usr/lib/llvm-19/lib/cmake/llvm

# LLVM linker flags: needed when manually linking binaries against vmlib built with JIT/AOT support.
# The cmake vmlib build links against LLVM_AVAILABLE_LIBS which includes Polly (separate from LLVM-19).
# Add Polly + ISL explicitly, then get the monolithic LLVM-19 + system libs from llvm-config.
if command -v llvm-config-19 >/dev/null 2>&1; then
  LLVM_LINK_FLAGS="$(llvm-config-19 --libs --system-libs 2>/dev/null)"
  LLVM_LDFLAGS="-L/usr/lib/llvm-19/lib -lPolly -lPollyISL $LLVM_LINK_FLAGS"
else
  LLVM_LDFLAGS="-L/usr/lib/llvm-19/lib -lPolly -lPollyISL -lLLVM-19"
fi

export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS OUT LLVM_DIR LLVM_LDFLAGS

cd "$SRC"

HARNESS_DIR="$SRC/mayhem/harnesses"
HARNESS_INC="-I$HARNESS_DIR"
WAMR_INC="-I$SRC/core/iwasm/include"

# ── Interpreter variants (no LLVM) ──────────────────────────────────────────────────────────────
# Common CMake args for pure-interpreter vmlib (no LLVM dependency).
interp_cmake_args=(
  -G Ninja
  -DCMAKE_C_COMPILER="$CC"
  -DCMAKE_CXX_COMPILER="$CXX"
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS"
  -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS"
  -DCMAKE_BUILD_TYPE=Debug
  # Pure interpreter: NO LLVM (AOT/JIT off).
  -DWAMR_BUILD_AOT=0
  -DWAMR_BUILD_JIT=0
  -DWAMR_BUILD_FAST_JIT=0
  -DWAMR_BUILD_INTERP=1
  # Match the OSS-Fuzz harness build options (ref types on, GC off, hw bound check off so the
  # loader/interpreter validates in software and ASan sees the OOB instead of a SIGSEGV trap).
  -DWAMR_BUILD_REF_TYPES=1
  -DWAMR_BUILD_GC=0
  -DWAMR_BUILD_SIMD=0
  -DWAMR_BUILD_LIBC_BUILTIN=1
  -DWAMR_BUILD_LIBC_WASI=0
  -DWAMR_DISABLE_HW_BOUND_CHECK=1
)

build_interp_variant() {
  local name="$1"        # e.g. wamr_fuzz_classic_interp
  local fast_interp="$2" # 0 or 1
  local builddir="$SRC/mayhem-build/$name"

  echo "=== configuring vmlib for $name (FAST_INTERP=$fast_interp) ==="
  cmake -S "product-mini/platforms/linux" -B "$builddir" \
    "${interp_cmake_args[@]}" \
    -DWAMR_BUILD_FAST_INTERP="$fast_interp"

  cmake --build "$builddir" --target vmlib -j"$MAYHEM_JOBS"

  local LIBVM
  LIBVM="$(find "$builddir" -name 'libiwasm.a' -o -name 'libvmlib.a' | head -1)"
  [ -n "$LIBVM" ] || { echo "FATAL: WAMR static lib not found for $name" >&2; exit 1; }
  echo "vmlib: $LIBVM"

  ASAN_OPTS_SRC="$HARNESS_DIR/asan_default_options.c"

  # libFuzzer target
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $HARNESS_INC $WAMR_INC \
      "$HARNESS_DIR/wasm_mutator_fuzz.cc" "$HARNESS_DIR/fuzzer_common.cc" "$ASAN_OPTS_SRC" \
      $LIB_FUZZING_ENGINE "$LIBVM" -lpthread -lm \
      -o "$OUT/$name"

  # standalone reproducer
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$builddir/standalone_main.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $HARNESS_INC $WAMR_INC \
      "$HARNESS_DIR/wasm_mutator_fuzz.cc" "$HARNESS_DIR/fuzzer_common.cc" "$ASAN_OPTS_SRC" \
      "$builddir/standalone_main.o" "$LIBVM" -lpthread -lm \
      -o "$OUT/$name-standalone"

  echo "built $name (+ standalone)"
}

build_interp_variant wamr_fuzz_classic_interp 0
build_interp_variant wamr_fuzz_fast_interp    1

# ── LLVM JIT variant ─────────────────────────────────────────────────────────────────────────────
# Uses the same wasm_mutator_fuzz.cc harness but builds vmlib with WAMR_BUILD_JIT=1 (LLVM MCJIT).
# ASan is stripped (LLVM ORC JIT emits code that bypasses ASan shadow mapping), UBSan stays.
# LLVM JIT also needs -fno-rtti (LLVM is built without RTTI).
build_llvm_jit() {
  local name="wamr_fuzz_llvm_jit"
  local builddir="$SRC/mayhem-build/$name"

  echo "=== configuring vmlib for $name (JIT=1, LLVM_DIR=$LLVM_DIR) ==="
  cmake -S "product-mini/platforms/linux" -B "$builddir" \
    -G Ninja \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$SANITIZER_FLAGS_NOSAN_ADDR $DEBUG_FLAGS" \
    -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS_NOSAN_ADDR $DEBUG_FLAGS -fno-rtti" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DWAMR_BUILD_JIT=1 \
    -DWAMR_BUILD_FAST_JIT=0 \
    -DWAMR_BUILD_INTERP=1 \
    -DWAMR_BUILD_AOT=1 \
    -DWAMR_BUILD_FAST_INTERP=1 \
    -DWAMR_BUILD_REF_TYPES=1 \
    -DWAMR_BUILD_GC=0 \
    -DWAMR_BUILD_SIMD=1 \
    -DWAMR_BUILD_LIBC_BUILTIN=1 \
    -DWAMR_BUILD_LIBC_WASI=0 \
    -DWAMR_DISABLE_HW_BOUND_CHECK=1 \
    -DLLVM_DIR="$LLVM_DIR"

  cmake --build "$builddir" --target vmlib -j"$MAYHEM_JOBS"

  local LIBVM
  LIBVM="$(find "$builddir" -name 'libiwasm.a' -o -name 'libvmlib.a' | head -1)"
  [ -n "$LIBVM" ] || { echo "FATAL: WAMR static lib not found for $name" >&2; exit 1; }
  echo "vmlib: $LIBVM"

  ASAN_OPTS_SRC="$HARNESS_DIR/asan_default_options.c"

  # libFuzzer target (no ASan for JIT; keep UBSan + fuzzer)
  $CXX $SANITIZER_FLAGS_NOSAN_ADDR $DEBUG_FLAGS -fno-rtti $HARNESS_INC $WAMR_INC \
      "$HARNESS_DIR/wasm_mutator_fuzz.cc" "$HARNESS_DIR/fuzzer_common.cc" "$ASAN_OPTS_SRC" \
      $LIB_FUZZING_ENGINE "$LIBVM" -lpthread -lm -ldl $LLVM_LDFLAGS \
      -o "$OUT/$name"

  # standalone reproducer
  $CC $SANITIZER_FLAGS_NOSAN_ADDR $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$builddir/standalone_main.o"
  $CXX $SANITIZER_FLAGS_NOSAN_ADDR $DEBUG_FLAGS -fno-rtti $HARNESS_INC $WAMR_INC \
      "$HARNESS_DIR/wasm_mutator_fuzz.cc" "$HARNESS_DIR/fuzzer_common.cc" "$ASAN_OPTS_SRC" \
      "$builddir/standalone_main.o" "$LIBVM" -lpthread -lm -ldl $LLVM_LDFLAGS \
      -o "$OUT/$name-standalone"

  echo "built $name (+ standalone)"
}

build_llvm_jit

# ── AOT compiler variant ──────────────────────────────────────────────────────────────────────────
# Uses aot_compiler_fuzz.cc which exercises the WAMR AOT compiler (compiles .wasm → native AOT,
# then loads and instantiates the AOT module). Needs LLVM for the compiler backend. ASan is safe
# here (the AOT compiler uses LLVM APIs, not the JIT's code-emit path).
build_aot_compiler() {
  local name="wamr_fuzz_aot_compiler"
  local builddir="$SRC/mayhem-build/$name"

  echo "=== configuring vmlib for $name (AOT compiler, LLVM_DIR=$LLVM_DIR) ==="
  # The AOT compiler variant needs: interp (to load bytecode), AOT (for aot_export.h APIs),
  # and the compilation module (iwasm_compl). WAMR_BUILD_JIT=0 (we use AOT offline compiler, not JIT).
  cmake -S "product-mini/platforms/linux" -B "$builddir" \
    -G Ninja \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$SANITIZER_FLAGS_NOSAN_ADDR $DEBUG_FLAGS" \
    -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS_NOSAN_ADDR $DEBUG_FLAGS -fno-rtti" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DWAMR_BUILD_JIT=1 \
    -DWAMR_BUILD_FAST_JIT=0 \
    -DWAMR_BUILD_INTERP=1 \
    -DWAMR_BUILD_AOT=1 \
    -DWAMR_BUILD_FAST_INTERP=0 \
    -DWAMR_BUILD_REF_TYPES=1 \
    -DWAMR_BUILD_GC=1 \
    -DWAMR_BUILD_SIMD=1 \
    -DWAMR_BUILD_LIBC_BUILTIN=1 \
    -DWAMR_BUILD_LIBC_WASI=0 \
    -DWAMR_DISABLE_HW_BOUND_CHECK=1 \
    -DLLVM_DIR="$LLVM_DIR"

  cmake --build "$builddir" --target vmlib -j"$MAYHEM_JOBS"

  local LIBVM
  LIBVM="$(find "$builddir" -name 'libiwasm.a' -o -name 'libvmlib.a' | head -1)"
  [ -n "$LIBVM" ] || { echo "FATAL: WAMR static lib not found for $name" >&2; exit 1; }
  echo "vmlib: $LIBVM"

  # AOT compiler harness needs aot_export.h (from AOT compilation module) and bh_read_file.h.
  AOT_INC="-I$SRC/core/iwasm/compilation -I$SRC/core/shared/utils/uncommon"

  ASAN_OPTS_SRC="$HARNESS_DIR/asan_default_options.c"

  # libFuzzer target
  $CXX $SANITIZER_FLAGS_NOSAN_ADDR $DEBUG_FLAGS -fno-rtti $HARNESS_INC $WAMR_INC $AOT_INC \
      "$HARNESS_DIR/aot_compiler_fuzz.cc" "$HARNESS_DIR/fuzzer_common.cc" "$ASAN_OPTS_SRC" \
      $LIB_FUZZING_ENGINE "$LIBVM" -lpthread -lm -ldl $LLVM_LDFLAGS \
      -o "$OUT/$name"

  # standalone reproducer
  $CC $SANITIZER_FLAGS_NOSAN_ADDR $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$builddir/standalone_main.o"
  $CXX $SANITIZER_FLAGS_NOSAN_ADDR $DEBUG_FLAGS -fno-rtti $HARNESS_INC $WAMR_INC $AOT_INC \
      "$HARNESS_DIR/aot_compiler_fuzz.cc" "$HARNESS_DIR/fuzzer_common.cc" "$ASAN_OPTS_SRC" \
      "$builddir/standalone_main.o" "$LIBVM" -lpthread -lm -ldl $LLVM_LDFLAGS \
      -o "$OUT/$name-standalone"

  echo "built $name (+ standalone)"
}

build_aot_compiler

# ── golden load/reject oracle for mayhem/test.sh ───────────────────────────────────────────────
# Link the small accept/reject oracle against the (classic-interp) instrumented libiwasm.a.
ORACLE_LIB="$(find "$SRC/mayhem-build/wamr_fuzz_classic_interp" -name 'libiwasm.a' -o -name 'libvmlib.a' | head -1)"
if [ -n "$ORACLE_LIB" ]; then
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $WAMR_INC \
      "$HARNESS_DIR/load_oracle.c" "$ORACLE_LIB" -lpthread -lm \
      -o "$OUT/wamr_load_oracle"
  echo "built wamr_load_oracle"
else
  echo "WARNING: could not find libiwasm.a for the oracle build" >&2
fi

echo "build.sh complete:"
ls -la "$OUT/wamr_fuzz_classic_interp" "$OUT/wamr_fuzz_fast_interp" \
       "$OUT/wamr_fuzz_llvm_jit" "$OUT/wamr_fuzz_aot_compiler" \
       "$OUT/wamr_fuzz_classic_interp-standalone" "$OUT/wamr_fuzz_fast_interp-standalone" \
       "$OUT/wamr_fuzz_llvm_jit-standalone" "$OUT/wamr_fuzz_aot_compiler-standalone" 2>&1 || true
