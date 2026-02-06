#!/bin/bash
./RP/routinator  \
  -vvvv \
  --allow-dubious-hosts \
  --no-rir-tals \
  --extra-tals-dir ./my_repo/ \
  -r ./rp_cache/routinator_cache \
  vrps \
  --format csv \
  --output ./rp_cache/routinator_output.csv

