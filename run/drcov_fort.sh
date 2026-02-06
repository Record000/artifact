#!/bin/bash
# Usage: ./drcov_fort.sh [logdir]
# Example: ./drcov_fort.sh ./drcov_output/tmp

LOGDIR=${1:-./drcov_output/tmp}

$DR_ROOT/bin64/drrun \
    -t drcov \
    -logdir "$LOGDIR" \
    -- \
    ./RP/fort \
    --mode=standalone \
    --tal=my_repo/rpki.tal \
    --local-repository=rp_cache/fort_cache \
    --http.enabled=false \
    --output.roa=- \
    --maximum-certificate-depth=102 \
    --log.enabled=true \
    --log.level=info \
    --validation-log.enabled=true \
    --validation-log.level=info

    