#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"

mkdir -p "$RESULTS_DIR"

echo "============================================"
echo "  Ring DNS Test Lab"
echo "============================================"
echo ""

# Default test parameters
BURST="${1:-30}"
SUSTAINED="${2:-100}"
SERVER="${3:-8.8.8.8}"

echo "Config: burst=$BURST sustained=$SUSTAINED server=$SERVER"
echo ""

# Run the stress test
swift "$SCRIPT_DIR/dns-stress/main.swift" \
    --burst "$BURST" \
    --sustained "$SUSTAINED" \
    --server "$SERVER" \
    --timeout 10 \
    --interval 50

echo ""
echo "Results saved in: $RESULTS_DIR/"
echo "To run with custom params:"
echo "  ./tests/run-lab.sh [burst_size] [sustained_count] [dns_server]"
echo "  ./tests/run-lab.sh 50 200 1.1.1.1"
