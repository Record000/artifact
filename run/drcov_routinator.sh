#!/bin/bash
# Usage: ./drcov_routinator.sh [logdir]
# Example: ./drcov_routinator.sh ./drcov_output/tmp

LOGDIR=${1:-./drcov_output/tmp}

$DR_ROOT/bin64/drrun \
    -t drcov \
    -logdir "$LOGDIR" \
    -- \
    ./RP/routinator   \
    -vvvv \
    --no-rir-tals \
    --extra-tals-dir ./my_repo/ \
    -r ./rp_cache/routinator_cache \
    --allow-dubious-hosts \
    vrps \
    --noupdate \
    --format csv \
    --output ./rp_cache/routinator_output.csv
