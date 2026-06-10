#!/usr/bin/env bash
#
# wamr/mayhem/test.sh — RUN the golden load/reject oracle (built by mayhem/build.sh) and emit a CTRF
# summary. exit 0 iff every oracle check passed.
#
# wamr ships no compact, self-contained pass/fail suite runnable at image-build time (its real tests
# are the external WebAssembly spec-test suite + sample apps needing a wasi toolchain). So this is the
# "golden oracle" path (procedure step 5, second option): mayhem/harnesses/load_oracle.c pins the
# loader's accept/reject contract — load+instantiate+run a byte-correct module (expect 42), reject a
# corrupted-magic module, reject a truncated module. It links the SAME instrumented libiwasm.a the
# fuzz targets use, so it also exercises the loader under ASan/UBSan. A no-op / "always succeed" patch
# to the loader fails the reject cases; a patch that breaks decoding fails the accept case. Not a stub.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${OUT:=/mayhem}"

ORACLE="$OUT/wamr_load_oracle"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-${SRC:-/mayhem}/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$ORACLE" ]; then
  echo "missing $ORACLE — run mayhem/build.sh first" >&2
  emit_ctrf "wamr-load-oracle" 0 1 0; exit 2
fi

echo "=== running wamr load/reject oracle ==="
out="$("$ORACLE" 2>&1)"; rc=$?
echo "$out"

# Parse the per-check "RESULT <name> PASS|FAIL" lines the oracle prints.
PASSED=$(printf '%s\n' "$out" | grep -c 'RESULT .* PASS')
FAILED=$(printf '%s\n' "$out" | grep -c 'RESULT .* FAIL')
: "${PASSED:=0}" "${FAILED:=0}"

# If we parsed no RESULT lines at all, fall back to the oracle's exit code (e.g. it crashed/aborted
# under a sanitizer before printing — that is a failure).
if [ "$(( PASSED + FAILED ))" -eq 0 ]; then
  echo "no RESULT lines parsed; using oracle exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "wamr-load-oracle" 1 0 0; exit 0; }
  emit_ctrf "wamr-load-oracle" 0 1 0; exit 1
fi

# A sanitizer abort (nonzero rc) with passing RESULT lines still counts as a failure.
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then
  echo "oracle exited $rc despite all RESULT lines passing (sanitizer abort?) — counting as failure" >&2
  FAILED=1
fi

emit_ctrf "wamr-load-oracle" "$PASSED" "$FAILED"
