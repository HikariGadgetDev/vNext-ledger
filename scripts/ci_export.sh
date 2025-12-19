#!/usr/bin/env bash
#
# Location:
#   MCP/vNext-ledger/scripts/ci_export.sh
#
# Output:
#   MCP/vNext-ledger/reports/YYYY-MM-DD/
#     - notes.json
#     - summary.json
#     - metrics.json
#
# Purpose:
#   Thin CI wrapper to export vNext Ledger artifacts
#   for periodic review (grant / PM report / CI).

set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8000}"
OUT_ROOT="${OUT_ROOT:-reports}"
DATE_DIR="${DATE_DIR:-$(date +%F)}"
OUT="${OUT_ROOT}/${DATE_DIR}"

mkdir -p "${OUT}"

# 差分 scan（full=0）
curl -sS -X POST "${BASE}/scan?full=0" \
  -H "Content-Type: application/json" \
  -d '{}' \
  > "${OUT}/scan.json"

# exports
curl -sS "${BASE}/export/summary" > "${OUT}/summary.json"
curl -sS "${BASE}/export/notes" > "${OUT}/notes.json"
curl -sS "${BASE}/export/metrics?limit=50" > "${OUT}/metrics.json"

echo "wrote ${OUT}"
