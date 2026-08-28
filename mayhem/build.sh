#!/usr/bin/env bash
#
# mayhem/build.sh — build userver's self-contained HTTP URL-argument parser
# (http::parser, universal/src/http/parser) as an in-process libFuzzer target,
# plus a clean behavioral-oracle probe.
#
# Fuzz target (byte-in, no file I/O):
#   fuzz_url_parser — http::parser::UrlDecode + ParseAndConsumeArgs over raw bytes
#
# WHY this component: userver is a giant async framework, but its `universal/` layer
# ships several genuinely self-contained parsers that need NO coroutine engine and NO
# framework. http::parser is the tightest: universal/src/http/parser/http_request_parse_args.cpp
# (the percent-decoder + query splitter) depends only on the header-only utils layer plus
# universal/src/utils/encoding/hex.cpp (FromHex). No postgres/redis/core build, no CMake
# closure — just three translation units.
#
# The PROJECT/runtime code is compiled with $SANITIZER_FLAGS AND -fsanitize=fuzzer-no-link
# UNCONDITIONALLY so the fuzzed parser carries SanCov instrumentation (else 0 edges in Mayhem),
# plus $DEBUG_FLAGS AFTER $SANITIZER_FLAGS so DWARF is <4 (the base's flags end in a plain -g =
# DWARF5). The oracle probe is a SEPARATE clean build (no sanitizer, no -gdwarf-3), dynamically
# linked so mayhem/test.sh's LD_PRELOAD sabotage shim can neuter it.
#
# userver injects its C++ namespace via -D compile definitions (universal/CMakeLists.txt sets
# USERVER_NAMESPACE / USERVER_NAMESPACE_BEGIN / USERVER_NAMESPACE_END); we reproduce them here.
# The only external dep is fmt (transitively via logging/log_filepath.hpp) — baked as a root apt
# layer in mayhem/Dockerfile, so this build runs fully offline / air-gap safe.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# ParseAndConsumeArgs deliberately forms a pointer one PAST one-past-the-end
# (`key_begin = ptr + 1` when `ptr == end`, http_request_parse_args.cpp) as a loop
# housekeeping step — the pointer is never dereferenced, but with the base's
# -fno-sanitize-recover=all UBSan's `pointer-overflow` check aborts on nearly every
# input that ends without a trailing '&', which would STARVE coverage (netnew §6b).
# Relax ONLY pointer-overflow; ASan and the rest of UBSan stay halting, and ASan remains
# the real detector for the OOB read/write bugs this parser target exists to find.
SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=pointer-overflow"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"

SRC="${SRC:-/mayhem}"
cd "$SRC"

INC="-I$SRC/universal/include -I$SRC/universal/src"
STD="-std=c++20"
# userver namespace, mirrored from universal/CMakeLists.txt (spaces/braces preserved via array).
NS=(
  -DUSERVER=1
  -DUSERVER_NAMESPACE=userver
  "-DUSERVER_NAMESPACE_BEGIN=namespace userver {"
  "-DUSERVER_NAMESPACE_END=}"
)
# -DNDEBUG turns userver's UASSERT into a no-op (kEnableAssert=false), so the parser keeps
# running on malformed input and ASan reaches real memory-safety bugs instead of debug asserts.
FUZZOPT="-O1 -DNDEBUG"

BUILD="$SRC/mayhem-build"
mkdir -p "$BUILD"

echo "== build.sh: SANITIZER_FLAGS=[$SANITIZER_FLAGS] DEBUG_FLAGS=[$DEBUG_FLAGS] =="

# Runtime translation units for the parser (the fuzzed code).
# http_request_parse_args.cpp also defines ParseArgs (unused by the harness) which pulls in
# utils::StrCaseHash — so the str_icase / siphash / rand trio comes along. All of these have
# only header-only deps (compiler/impl/tls.hpp, assert.hpp), so the closure stays tiny — no
# coroutine engine, no framework.
RT_SRCS=(
  "universal/src/http/parser/http_request_parse_args.cpp"
  "universal/src/utils/encoding/hex.cpp"
  "universal/src/utils/str_icase.cpp"
  "universal/src/utils/impl/byte_utils.cpp"
  "universal/src/utils/rand.cpp"
)

objname() { echo "$BUILD/$(echo "$1" | tr '/.' '__')$2.o"; }

# ---------------------------------------------------------------------------
# 1) Sanitized runtime objects (fuzz build) — instrumented + DWARF<4
# ---------------------------------------------------------------------------
SAN_OBJS=()
for f in "${RT_SRCS[@]}"; do
  o="$(objname "$f" .san)"
  $CXX $STD $FUZZOPT $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "${NS[@]}" $INC -c "$SRC/$f" -o "$o"
  SAN_OBJS+=("$o")
done

# Standalone run-once driver (C file) — compiled once, linked into the standalone reproducer.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/standalone_main.o"

build_target() {
  local name="$1"
  local hobj="$BUILD/$name.san.o"
  $CXX $STD $FUZZOPT $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "${NS[@]}" $INC \
      -c "$SRC/mayhem/harnesses/$name.cpp" -o "$hobj"
  # fuzzer binary
  $CXX $STD $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
      "$hobj" "${SAN_OBJS[@]}" -o "/mayhem/$name"
  # standalone run-once reproducer
  $CXX $STD $SANITIZER_FLAGS $DEBUG_FLAGS \
      "$BUILD/standalone_main.o" "$hobj" "${SAN_OBJS[@]}" -o "/mayhem/$name-standalone"
}

build_target fuzz_url_parser

# ---------------------------------------------------------------------------
# 2) Oracle probe — CLEAN build (NORMAL flags; NO sanitizer, NO -gdwarf-3),
#    dynamically linked so mayhem/test.sh's LD_PRELOAD sabotage shim can neuter it.
# ---------------------------------------------------------------------------
CLEAN_OBJS=()
for f in "${RT_SRCS[@]}"; do
  o="$(objname "$f" .clean)"
  $CXX $STD -O2 -DNDEBUG "${NS[@]}" $INC -c "$SRC/$f" -o "$o"
  CLEAN_OBJS+=("$o")
done
$CXX $STD -O2 -DNDEBUG "${NS[@]}" $INC "$SRC/mayhem/probes/url_probe.cpp" \
    "${CLEAN_OBJS[@]}" -o /mayhem/url_probe

if ! file /mayhem/url_probe | grep -q 'dynamically linked'; then
  echo "FATAL: /mayhem/url_probe is not dynamically linked — oracle would be un-neuterable" >&2
  file /mayhem/url_probe >&2
  exit 1
fi

echo "== build.sh: OK =="
ls -l /mayhem/fuzz_url_parser /mayhem/fuzz_url_parser-standalone /mayhem/url_probe
