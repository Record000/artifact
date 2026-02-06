#!/bin/bash
#
# Artifact Docker Entrypoint
#

set -e

# Set umask to ensure new files are readable by all users
# This is needed because rpki-client drops privileges to _rpki-client user
umask 000

# Create _rpki-client user required by rpki-client
if ! id -u _rpki-client >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /bin/false _rpki-client 2>/dev/null || \
    adduser --system --no-create-home --shell /bin/false _rpki-client 2>/dev/null || \
    echo "Warning: Could not create _rpki-client user"
fi

# Copy RPKI validators from /opt/rp-validators to /workspace/RP
# This happens on every container start to ensure they're available
if [ -d /opt/rp-validators ] && [ "$(ls -A /opt/rp-validators)" ]; then
    mkdir -p /workspace/RP
    for validator in /opt/rp-validators/*; do
        if [ -f "$validator" ]; then
            cp "$validator" /workspace/RP/
            echo "Copied $(basename "$validator") to /workspace/RP/"
        fi
    done
fi

# Start rsync service
if [ -f /etc/rsyncd.conf ]; then
    # Create rsync pid directory
    mkdir -p /tmp
    # Start rsync in daemon mode
    rsync --daemon --config=/etc/rsyncd.conf
    echo "rsync service started on 127.0.0.1:8730"
fi

# Fix permissions for rpki-client (which drops privileges to _rpki-client user)
# Make workspace files readable and writable by all users
if [ -d /workspace ]; then
    chmod -R a+rX /workspace 2>/dev/null || true
    chmod -R a+rw /workspace 2>/dev/null || true
fi

# Execute the command passed to the container
exec "$@"
