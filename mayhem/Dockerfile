# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile for userver's self-contained HTTP URL-argument parser
# (http::parser), built ON TOP of the org C/C++ base. The base provides clang/llvm +
# libFuzzer + the build-contract ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/
# STANDALONE_FUZZ_MAIN/SRC).
#
# userver is a giant async framework, but its universal/ layer ships genuinely
# self-contained parsers. We build ONLY http::parser (3 translation units under
# universal/src) — NOT the coroutine engine, framework, or postgres/redis. The only
# external dependency is fmt (pulled transitively by userver/logging/log_filepath.hpp),
# baked here as a root apt layer so mayhem/build.sh runs fully offline / air-gap safe.
FROM ghcr.io/savantenvs/base:20260621

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG MAYHEM_JOBS=

USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
    apt-get update \
 && apt-get install -y --no-install-recommends libfmt-dev \
 && rm -rf /var/lib/apt/lists/*

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
