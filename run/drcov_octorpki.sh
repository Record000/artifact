#!/bin/bash
# Usage: ./drcov_octorpki.sh [logdir]
# Example: ./drcov_octorpki.sh ./drcov_output/tmp

LOGDIR=${1:-./drcov_output/tmp}

$DR_ROOT/bin64/drrun \
    -t drcov \
    -logdir "$LOGDIR" \
    -- \
    ./RP/octorpki \
    -allow.root \
    -mode oneoff \
    -tal.root "./my_repo/rpki.tal" \
    -tal.name "artifact_root" \
    -cache "./rp_cache/octorpki_cache" \
    -output.roa "./rp_cache/octorpki_output.json" \
    -output.sign=false 
