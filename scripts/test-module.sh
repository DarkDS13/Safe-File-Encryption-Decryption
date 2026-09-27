#!/usr/bin/env bash
# Run the tests for one module of the design document.
#
#   ./scripts/test-module.sh 0.1        one module
#   ./scripts/test-module.sh devansh    every module one person owns
#   ./scripts/test-module.sh            list what is available
set -euo pipefail
cd "$(dirname "$0")/.."

PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
VECTORS="frontend/tests/crypto-vectors.test.mjs"

py()   { $PY -m pytest "$@" -q; }
node_() { node --test --test-name-pattern="$1" "$VECTORS"; }

case "${1:-}" in
  0.1) echo "0.1 Authentication & Session Management  (Devansh, F.12)"
       py backend/tests/test_auth.py ;;
  0.2) echo "0.2 Key Derivation  (Samarth, F.2 F.3)"
       node_ "Argon2|BLAKE2b" ;;
  0.3) echo "0.3 Segmentation & Encryption  (Samarth, F.1 F.4 F.5 F.6 F.9)"
       node_ "file validation" ;;
  0.4) echo "0.4 Container Storage & Retrieval  (Devansh, F.7 F.11)"
       py backend/tests/test_containers.py backend/tests/test_storage.py ;;
  0.5) echo "0.5 Verification & Decryption  (Jay, F.8 F.9)"
       node_ "failure paths|SHA-256" ;;
  0.6) echo "0.6 Metrics & Audit Logging  (Jay, F.10 F.14)"
       py backend/tests/test_operations.py ;;
  0.7) echo "0.7 System Administration  (Devansh, F.13)"
       py backend/tests/test_admin.py ;;

  contract)    echo "Container format — the 0.3 / 0.5 contract"
               node_ "container format" ;;
  integration) echo "Integration — encrypt/decrypt round trip (NF.4)"
               node_ "round trip" ;;
  infra)       echo "Cross-cutting — rate limiting and concurrency (NF.6)"
               py backend/tests/test_ratelimit.py backend/tests/test_concurrency.py ;;
  system)      echo "System — performance and bounded memory (NF.5, C.4)"
               node --test frontend/tests/performance.test.mjs ;;

  devansh) "$0" 0.1; "$0" 0.4; "$0" 0.7; "$0" infra ;;
  samarth) "$0" 0.2; "$0" 0.3 ;;
  jay)     "$0" 0.5; "$0" 0.6 ;;

  *) cat <<'USAGE'
Modules:
  0.1  Authentication & Session Management   Devansh    22 tests
  0.2  Key Derivation                        Samarth     7
  0.3  Segmentation & Encryption             Samarth     5
  0.4  Container Storage & Retrieval         Devansh    24
  0.5  Verification & Decryption             Jay        10
  0.6  Metrics & Audit Logging               Jay         8
  0.7  System Administration                 Devansh    13

Shared and cross-cutting:
  contract     container format, the 0.3/0.5 seam        7
  integration  encrypt/decrypt round trip (NF.4)         9
  infra        rate limiting, concurrency (NF.6)        15
  system       performance, bounded memory (NF.5, C.4)   5

By person:  devansh (74)   samarth (12)   jay (18)
Everything: ./scripts/test.sh            125
USAGE
     ;;
esac
