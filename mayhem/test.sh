#!/usr/bin/env bash
#
# mayhem/test.sh — behavioral oracle for userver's http::parser URL parser.
#
# Runs the CLEAN (non-sanitized), dynamically-linked url_probe built by mayhem/build.sh.
# The probe drives the SAME code the fuzzer hits (http::parser::UrlDecode /
# ParseAndConsumeArgs) on FIXED inputs and prints the parsed result. These are
# known-answer decodes: a PATCH that neuters the parser to a no-op / exit(0) (or the
# verify-repo LD_PRELOAD sabotage shim) prints nothing, so every assertion FAILS.
#
# Emits a CTRF summary + a compact `CTRF {...}` stdout marker; exits non-zero iff failed>0.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
SRC="${SRC:-/mayhem}"
cd "$SRC"

P=/mayhem/url_probe

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
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

# Fail loudly if build.sh did not produce the probe (a build bug, not a skip).
if [ ! -x "$P" ]; then
  echo "FATAL: $P missing/not executable — mayhem/build.sh did not build the oracle" >&2
  emit_ctrf "userver-urlparse-kat" 0 1 0
  exit 1
fi

passed=0
failed=0
assert() {
  local label="$1" want="$2" got="$3"
  if [ "$got" = "$want" ]; then
    echo "PASS  $label -> '$got'"
    passed=$((passed + 1))
  else
    echo "FAIL  $label : want='$want' got='$got'"
    failed=$((failed + 1))
  fi
}

# Known-answer percent-decodes through http::parser::UrlDecode.
assert "decode %20"     "a b"        "$("$P" decode 'a%20b'      2>/dev/null)"
assert "decode hex ABC" "ABC"        "$("$P" decode '%41%42%43'  2>/dev/null)"
assert "decode plus"    "foo bar"    "$("$P" decode 'foo+bar'    2>/dev/null)"
assert "decode percent" "100%x"      "$("$P" decode '100%25x'    2>/dev/null)"

# Malformed escape must throw (strict decoder) — the probe reports it as THROW:...
bad="$("$P" decode 'bad%zz' 2>/dev/null)"
case "$bad" in
  THROW:*invalid\ percent-encoding*) echo "PASS  decode strict-throw -> '$bad'"; passed=$((passed + 1)) ;;
  *) echo "FAIL  decode strict-throw : want THROW/invalid percent-encoding got='$bad'"; failed=$((failed + 1)) ;;
esac

# Query-string split + per-field decode through ParseAndConsumeArgs.
args1="$("$P" args 'x=1&y=hello%20world' 2>/dev/null)"
if printf '%s\n' "$args1" | grep -qx 'x=1' && printf '%s\n' "$args1" | grep -qx 'y=hello world'; then
  echo "PASS  args split+decode -> [$args1]"; passed=$((passed + 1))
else
  echo "FAIL  args split+decode : want 'x=1' and 'y=hello world' got=[$args1]"; failed=$((failed + 1))
fi

assert "args %2B->plus" "a=b+c" "$("$P" args 'a=b%2Bc' 2>/dev/null)"

emit_ctrf "userver-urlparse-kat" "$passed" "$failed" 0
