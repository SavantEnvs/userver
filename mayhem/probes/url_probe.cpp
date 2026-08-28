// url_probe.cpp — behavioral oracle for the http::parser URL parser.
//
// A small, CLEAN (non-sanitized), DYNAMICALLY-LINKED program driving the SAME
// code the fuzzer hits: http::parser::UrlDecode and ParseAndConsumeArgs. It runs
// fixed inputs and prints the parsed result to stdout, so mayhem/test.sh can
// assert known-answer values with plain bash/coreutils.
//
// Dynamically linked on purpose: verify-repo's LD_PRELOAD sabotage shim neuters
// every non-system executable to _exit(0). A neutered probe prints NOTHING, so
// every assertion in test.sh FAILS — proving the oracle is behavioral.
//
// Usage:
//   url_probe decode <string>   -> prints UrlDecode(string)
//   url_probe args   <string>   -> prints one "key=value" line per parsed arg

#include <cstdio>
#include <cstring>
#include <exception>
#include <string>
#include <string_view>

#include <userver/http/parser/http_request_parse_args.hpp>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <decode|args> <string>\n", argv[0]);
        return 2;
    }

    const std::string_view mode = argv[1];
    const std::string_view input = argv[2];

    try {
        if (mode == "decode") {
            const std::string out = USERVER_NAMESPACE::http::parser::UrlDecode(input);
            std::fwrite(out.data(), 1, out.size(), stdout);
            std::fputc('\n', stdout);
        } else if (mode == "args") {
            USERVER_NAMESPACE::http::parser::ParseAndConsumeArgs(
                input,
                [](std::string&& key, std::string&& value) {
                    std::printf("%s=%s\n", key.c_str(), value.c_str());
                }
            );
        } else {
            std::fprintf(stderr, "unknown mode: %.*s\n", static_cast<int>(mode.size()), mode.data());
            return 2;
        }
    } catch (const std::exception& e) {
        std::printf("THROW:%s\n", e.what());
    }

    return 0;
}
