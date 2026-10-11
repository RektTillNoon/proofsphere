#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
export RISC0_HOME="$PWD/.proofsphere-tools/risc0"
export RISC0_BUILD_LOCKED=1
export PATH="$PWD/tools/build-bin:$PWD/.proofsphere-tools/bin:$PATH"
exec cargo "$@"
