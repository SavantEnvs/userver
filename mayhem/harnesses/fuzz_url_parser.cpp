// fuzz_url_parser.cpp — byte-in libFuzzer harness for userver's self-contained
// HTTP URL-argument parser (http::parser, universal/src/http/parser).
//
// Exercises the strict percent-decoder http::parser::UrlDecode and the query-string
// splitter http::parser::ParseAndConsumeArgs (which itself calls UrlDecode on every
// key/value). These live entirely in universal/ and pull in ONLY the header-only
// utils layer + userver/utils/encoding/hex.cpp — no coroutine engine, no framework,
// no postgres/redis. The parser takes bytes straight from the fuzzer; NO file I/O.
//
// UrlDecode THROWS std::runtime_error on a malformed percent-escape, so both calls
// are wrapped: an exception is normal control flow, not a finding. A memory-safety
// bug (OOB read past the buffer while scanning "%", hex lookahead, '+' handling)
// surfaces as an ASan/UBSan abort, which is the point.

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>
#include <string_view>

#include <userver/http/parser/http_request_parse_args.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string_view input(reinterpret_cast<const char*>(data), size);

    // 1) Strict percent-decoder on the raw bytes.
    try {
        const std::string decoded = USERVER_NAMESPACE::http::parser::UrlDecode(input);
        // Touch the result so the decode can't be optimized away.
        if (!decoded.empty() && decoded[0] == '\0') {
            // no-op; just a data-dependent branch
        }
    } catch (const std::exception&) {
        // malformed percent-encoding — expected, not a defect
    }

    // 2) Full query-string split + per-field decode via the consumer API
    //    (no StrCaseHash container needed — a plain lambda sink).
    try {
        std::size_t acc = 0;
        USERVER_NAMESPACE::http::parser::ParseAndConsumeArgs(
            input, [&acc](std::string&& key, std::string&& value) { acc += key.size() + value.size(); }
        );
        (void)acc;
    } catch (const std::exception&) {
        // malformed key/value percent-encoding — expected
    }

    return 0;
}
