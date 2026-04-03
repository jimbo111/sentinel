#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$(dirname "$SCRIPT_DIR")/backend"

echo "Generating RS256 JWT key pair for Ring backend..."

openssl genrsa -out "$BACKEND_DIR/private.pem" 2048 2>/dev/null
openssl rsa -in "$BACKEND_DIR/private.pem" -pubout -out "$BACKEND_DIR/public.pem" 2>/dev/null

echo "Keys generated:"
echo "  Private: $BACKEND_DIR/private.pem"
echo "  Public:  $BACKEND_DIR/public.pem"
echo ""
echo "To use with docker-compose, create backend/.env:"
echo ""
echo "  JWT_PRIVATE_KEY=\"\$(awk 'NF {sub(/\\r/, \"\"); printf \"%s\\\\n\",\$0;}' $BACKEND_DIR/private.pem)\""
echo "  JWT_PUBLIC_KEY=\"\$(awk 'NF {sub(/\\r/, \"\"); printf \"%s\\\\n\",\$0;}' $BACKEND_DIR/public.pem)\""
