# =============================================================================
# Artifact - RPKI Fuzzing Framework
# Dockerfile for reproducing RPKI validator experiments
# =============================================================================
# Usage:
#   docker build -t artifact:latest -f docker/Dockerfile .
#   docker run -it --rm -v $(pwd):/workspace artifact:latest bash
#
# This Dockerfile supports running 4 experimental scripts in mutation/:
#   1. main.py - Mutation repair mode with timing measurement
#   2. test_coverage.py - Multi-stage pass rate coverage (fix/nofix modes)
#   3. test_noDep.py - Mutation without repair mode
#   4. test_mutate_times_3.py - Multi-threading performance test
#
# Requirements:
#   - RP/instruct/ directory must contain instrumented validator binaries
#     These binaries output FUZZ_METRIC for coverage testing
#     They are pre-compiled on the host and copied into the image
#     (NOT compiled inside the container)
#
# See docker/EXPERIMENT_SETUP.md for detailed usage instructions
# =============================================================================

FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# =============================================================================
# 1. System Dependencies (build tools)
# =============================================================================
RUN apt-get update && apt-get install -y \
    # Build tools
    build-essential \
    cmake \
    git \
    wget \
    curl \
    # Python environment
    python3 \
    python3-pip \
    # Network and sync tools
    rsync \
    # Coverage tools
    lcov \
    # Dependencies for RPKI validators
    libssl-dev \
    libcurl4-openssl-dev \
    pkg-config \
    libjansson-dev \
    libxml2-dev \
    libmicrohttpd-dev \
    # For rpki-client (libtls from libressl)
    libtls-dev \
    # For building rpki-client and FORT
    automake \
    autoconf \
    bison \
    libtool \
    # Additional dependencies for FORT Validator
    libexpat1-dev \
    # Dependencies for matplotlib (for draw_pics scripts)
    libfreetype6-dev \
    libpng-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust via rustup (for latest stable version)
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH="/usr/local/cargo/bin:${PATH}"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal && \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME && \
    rustup --version && \
    cargo --version && \
    rustc --version

# Install Go (from tmp/, version detected dynamically)
ARG GO_PKG=go.tar.gz
COPY tmp/${GO_PKG} /tmp/
RUN tar -C /usr/local -xzf /tmp/${GO_PKG} && \
    rm /tmp/${GO_PKG} && \
    ln -sf /usr/local/go/bin/go /usr/local/bin/go && \
    ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt

ENV PATH="/usr/local/go/bin:${PATH}"

# =============================================================================
# 2. Python Packages
# =============================================================================
RUN pip3 install --no-cache-dir \
    cryptography \
    asn1crypto \
    pyasn1 \
    pyasn1-modules \
    lxml \
    matplotlib \
    numpy \
    pandas \
    iso8601 \
    tqdm

# Create python -> python3 symlink for convenience
RUN ln -sf /usr/bin/python3 /usr/bin/python

# =============================================================================
# 3. DynamoRIO (for code coverage experiments)
# =============================================================================
ARG DYNAMORIO_PKG=DynamoRIO.tar.gz
ENV DR_ROOT=/opt/dynamorio

COPY tmp/${DYNAMORIO_PKG} /tmp/
RUN cd /tmp && \
    tar xzf ${DYNAMORIO_PKG} && \
    TOP_DIR=$(tar -tzf ${DYNAMORIO_PKG} | head -1 | cut -f1 -d"/") && \
    mv "$TOP_DIR" ${DR_ROOT} && \
    rm -f ${DYNAMORIO_PKG}

ENV PATH="${DR_ROOT}/bin64:${PATH}"

# =============================================================================
# 4. RPKI Validators (build from source in tmp/)
# =============================================================================

# Build arguments for package names (detected dynamically)
ARG ROUTINATOR_PKG=routinator.tar.gz
ARG FORT_PKG=fort.tar.gz
ARG RPKI_CLIENT_PKG=rpki-client.tar.gz
ARG CFRPKI_PKG=cfrpki.tar.gz

# Copy all source tarballs from tmp/
COPY tmp/${ROUTINATOR_PKG} /tmp/
COPY tmp/${FORT_PKG} /tmp/
COPY tmp/${RPKI_CLIENT_PKG} /tmp/
COPY tmp/${CFRPKI_PKG} /tmp/

# Store validators in /opt/rp-validators (outside /workspace to avoid volume mount overlap)
RUN mkdir -p /opt/rp-validators

# Extract all source packages
RUN cd /tmp && tar xzf ${ROUTINATOR_PKG}
RUN cd /tmp && tar xzf ${FORT_PKG}
RUN cd /tmp && tar xzf ${RPKI_CLIENT_PKG}
RUN cd /tmp && tar xzf ${CFRPKI_PKG}

# --- Routinator ---
RUN cd /tmp && \
    TOP_DIR=$(tar -tzf ${ROUTINATOR_PKG} | head -1 | cut -f1 -d"/") && \
    cd "$TOP_DIR" && \
    cargo build --release && \
    cp target/release/routinator /opt/rp-validators/ && \
    cd / && rm -rf "/tmp/$TOP_DIR"

# --- FORT Validator ---
RUN cd /tmp && \
    TOP_DIR=$(tar -tzf ${FORT_PKG} | head -1 | cut -f1 -d"/") && \
    cd "$TOP_DIR" && \
    ./configure && \
    make -j$(nproc) && \
    cp src/fort /opt/rp-validators/ && \
    cd / && rm -rf "/tmp/$TOP_DIR"

# --- rpki-client ---
RUN cd /tmp && \
    TOP_DIR=$(tar -tzf ${RPKI_CLIENT_PKG} | head -1 | cut -f1 -d"/") && \
    cd "$TOP_DIR" && \
    ./configure && \
    make -j$(nproc) && \
    cp src/rpki-client /opt/rp-validators/ && \
    cd / && rm -rf "/tmp/$TOP_DIR"

# --- OctoRPKI (with patches) ---
COPY docker/octorpki-rsync.patch /tmp/octorpki-rsync.patch
RUN cd /tmp && \
    TOP_DIR=$(tar -tzf ${CFRPKI_PKG} | head -1 | cut -f1 -d"/") && \
    cd "$TOP_DIR" && \
    patch -p1 < /tmp/octorpki-rsync.patch && \
    cd cmd/octorpki && \
    go build -o /opt/rp-validators/octorpki . && \
    cd / && rm -rf "/tmp/$TOP_DIR" /tmp/*.tar.gz /tmp/octorpki-rsync.patch

# Verify all validators were built
RUN ls -la /opt/rp-validators/ && \
    echo "✓ All RPKI validators built successfully"

# =============================================================================
# 4.5 Instrumented RPKI Validators (mounted from host)
# =============================================================================
# Instrumented validators are NOT included in the image.
# They are mounted from the host via volume mount at /workspace/RP/instruct/
# This allows updating binaries without rebuilding the image.
#
# The entrypoint.sh script will verify they exist after container starts.
# See docker-run.sh for the volume mount configuration.

# =============================================================================
# 5. Entrypoint Script & rsync Service
# =============================================================================
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Copy rsync configuration
COPY rsyncd.conf /etc/rsyncd.conf

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# =============================================================================
# 6. Environment Variables
# =============================================================================
ENV PATH="/workspace:${PATH}"

# =============================================================================
# 7. Working Directory
# =============================================================================
WORKDIR /workspace

# =============================================================================
# 7. Default Command
# =============================================================================
CMD ["/bin/bash"]
