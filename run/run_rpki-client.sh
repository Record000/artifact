#!/bin/bash
# Fix permissions for rpki-client (drops privileges to _rpki-client user)
chmod -R a+rX my_repo rp_cache 2>/dev/null || true

./RP/rpki-client -t ./my_repo/rpki.tal \
    -d ./rp_cache/rpki-client_cache \
    -vv ./rp_cache/rpki-client_output
