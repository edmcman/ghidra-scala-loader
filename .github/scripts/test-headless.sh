#!/usr/bin/env bash
set -euo pipefail

: "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR to the Ghidra installation}"
log_dir=${LOG_DIR:-logs}
mkdir -p "$log_dir"
project_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/scala-loader-test.XXXXXX")
trap 'rm -rf "$project_dir"' EXIT

"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
  "$project_dir" TestProject \
  -import /bin/ls \
  -noanalysis \
  -postScript HelloWorldScript.scala \
  -deleteProject 2>&1 | tee "$log_dir/headless.log"

grep -Fq "Hello world, I'm written in Scala 3!" "$log_dir/headless.log"
