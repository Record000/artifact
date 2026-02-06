#!/bin/bash

./RP/octorpki \
  -allow.root \
  -mode oneoff \
  -tal.root "./my_repo/rpki.tal" \
  -tal.name "artifact_root" \
  -cache "./rp_cache/octorpki_cache" \
  -output.roa "./rp_cache/octorpki_output.json" \
  -output.sign=false \
  -loglevel debug
