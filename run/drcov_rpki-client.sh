#!/bin/bash
# Usage: ./drcov_rpki-client.sh [logdir]
# Example: ./drcov_rpki-client.sh ./drcov_output/tmp

LOGDIR=${1:-./drcov_output/tmp}

# Fix permissions for rpki-client (drops privileges to _rpki-client user)
chmod -R a+rX my_repo rp_cache 2>/dev/null || true

$DR_ROOT/bin64/drrun \
    -t drcov \
    -logdir "$LOGDIR" \
    -- \
    ./RP/rpki-client  -t ./my_repo/rpki.tal \
    -d ./rp_cache/rpki-client_cache \
    -vv ./rp_cache/rpki-client_output
