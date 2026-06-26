#!/usr/bin/env bash
# Limpia ejecuciones de prueba que se hayan quedado a medias.
# Algunas pueden pertenecer a root si se lanzaron experimentos con sudo.
# Run manually: bash scripts/cleanup_local_results.sh

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/results"

echo "Removing debug run folders and loose PCAPs (keeping run_20260626)..."

for dir in 20260626_003818 20260626_003904 20260626_011656 20260626_XXXXXX dns_clean_test doq_fix_test analysis; do
  if [ -d "$dir" ]; then
    rm -rf "$dir" 2>/dev/null || sudo rm -rf "$dir"
  fi
done

for f in dns_*.pcap dns_results.csv; do
  [ -e "$f" ] || continue
  rm -f "$f" 2>/dev/null || sudo rm -f "$f"
done

echo "Done. Remaining in results/:"
ls -la
