#!/usr/bin/env bash
# One command from a fresh clone to a working beast-boot dev environment:
#   scripts/dev-setup.sh --yes      (same as `make dev` / `bin/bb-dev setup --yes`)
# Never needs root. Options: bin/bb-dev setup --help
set -euo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin/bb-dev" setup "$@"
