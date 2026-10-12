#!/bin/bash
# Fresh installation only. Existing installations belong to the upgrader.
set -euo pipefail
SCRIPTDIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
  echo "v0.34-dev fresh installer: read-only preflight by default."
  echo "Flags: --check | --install-prerequisites | --apply --bootstrap-stock-nft"
  echo "Profiles: --ssh [--ssh-port 22] --docker --npm-log-dir /PATH --mail-to ADDRESS"
  echo "Existing installation detected? Use scripts/upgrade-v033-v034.py instead."
  exit 0
fi
if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo" >&2
  exit 1
fi
if [[ ! -x /usr/bin/python3 ]]; then
  echo "Missing bootstrap dependency: python3. Install explicitly: sudo apt-get install python3" >&2
  exit 1
fi
echo "Fail2Ban v0.34-dev — fresh install preflight (not an upgrade/cleanup tool)"
exec /usr/bin/python3 "$SCRIPTDIR/scripts/fresh-install.py" "$@"
