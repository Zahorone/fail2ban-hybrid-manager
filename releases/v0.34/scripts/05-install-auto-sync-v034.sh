#!/usr/bin/env bash
set -euo pipefail

# Fail2Ban owns its per-jail action sets. Initial shared-set reconciliation
# uses the same runtime authority and expiry handling as the scheduled sync.
if [[ "$EUID" -ne 0 ]]; then
  echo "Run with sudo" >&2
  exit 1
fi
if [[ ! -f /usr/local/sbin/f2b-ipv6-sync.py ]]; then
  echo "Install the v0.34 wrapper/helper component first" >&2
  exit 1
fi
/usr/bin/python3 /usr/local/sbin/f2b-ipv6-sync.py
echo "PASS: initial IPv4/IPv6 Docker and recidive reconciliation"
