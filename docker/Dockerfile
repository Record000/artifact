# =============================================================================
# Artifact - RPKI Fuzzing Framework
# Dockerfile for reproducing RPKI validator experiments
# =============================================================================
# Usage:
#   docker build -t artifact:latest -f docker/Dockerfile .
#   docker run -it --rm -v $(pwd):/workspace artifact:latest bash
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
    # For rpki-client
    libtls-dev \
    # For building rpki-client
    automake \
    autoconf \
    bison \
    libtool \
    # Cargo for routinator
    cargo \
    && rm -rf /var/lib/apt/lists/*

# Install Go (from tmp/, version detected dynamically)
ARG GO_PKG=go1.25.7.linux-amd64.tar.gz
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
    asn1crypto

# =============================================================================
# 3. DynamoRIO (for code coverage experiments)
# =============================================================================
ARG DYNAMORIO_PKG=DynamoRIO-Linux-11.90.20482.tar.gz
ENV DR_ROOT=/opt/dynamorio

COPY tmp/${DYNAMORIO_PKG} /tmp/
RUN cd /tmp && \
    tar xzf ${DYNAMORIO_PKG} && \
    mv $(tar -tzf ${DYNAMORIO_PKG} | head -1 | cut -f1 -d"/") ${DR_ROOT} && \
    rm ${DYNAMORIO_PKG}

ENV PATH="${DR_ROOT}/bin64:${PATH}"

# =============================================================================
# 4. RPKI Validators (build from source in tmp/)
# =============================================================================

# Build arguments for package names (detected dynamically)
ARG ROUTINATOR_PKG=routinator-0.14.2.tar.gz
ARG FORT_PKG=fort-1.6.7.tar.gz
ARG RPKI_CLIENT_PKG=rpki-client-9.6.tar.gz
ARG CFRPKI_PKG=cfrpki-1.5.10.tar.gz

# Copy all source tarballs from tmp/
COPY tmp/${ROUTINATOR_PKG} /tmp/
COPY tmp/${FORT_PKG} /tmp/
COPY tmp/${RPKI_CLIENT_PKG} /tmp/
COPY tmp/${CFRPKI_PKG} /tmp/

# Store validators in /opt/rp-validators (outside /workspace to avoid volume mount overlap)
RUN mkdir -p /opt/rp-validators

# --- Routinator ---
RUN cd /tmp && \
    tar xzf ${ROUTINATOR_PKG} && \
    cd $(tar -tzf ${ROUTINATOR_PKG} | head -1 | cut -f1 -d"/") && \
    cargo build --release && \
    cp target/release/routinator /opt/rp-validators/ && \
    cd / && rm -rf /tmp/$(tar -tzf ${ROUTINATOR_PKG} | head -1 | cut -f1 -d"/") ${ROUTINATOR_PKG}

# --- FORT Validator ---
RUN cd /tmp && \
    tar xzf ${FORT_PKG} && \
    cd $(tar -tzf ${FORT_PKG} | head -1 | cut -f1 -d"/") && \
    ./configure && \
    make -j$(nproc) && \
    cp src/fort /opt/rp-validators/ && \
    cd / && rm -rf /tmp/$(tar -tzf ${FORT_PKG} | head -1 | cut -f1 -d"/") ${FORT_PKG}

# --- rpki-client ---
RUN cd /tmp && \
    tar xzf ${RPKI_CLIENT_PKG} && \
    cd $(tar -tzf ${RPKI_CLIENT_PKG} | head -1 | cut -f1 -d"/") && \
    ./configure --with-libtls=libretls && \
    make -j$(nproc) && \
    cp src/rpki-client /opt/rp-validators/ && \
    cd / && rm -rf /tmp/$(tar -tzf ${RPKI_CLIENT_PKG} | head -1 | cut -f1 -d"/") ${RPKI_CLIENT_PKG}

# --- OctoRPKI (with patches) ---
COPY docker/octorpki-rsync.patch /tmp/octorpki-rsync.patch
RUN cd /tmp && \
    tar xzf ${CFRPKI_PKG} && \
    cd $(tar -tzf ${CFRPKI_PKG} | head -1 | cut -f1 -d"/") && \
    patch -p1 < /tmp/octorpki-rsync.patch && \
    cd cmd/octorpki && \
    go build -o /opt/rp-validators/octorpki . && \
    cd / && rm -rf /tmp/$(tar -tzf ${CFRPKI_PKG} | head -1 | cut -f1 -d"/") /tmp/octorpki-rsync.patch ${CFRPKI_PKG}

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
ENV DR_ROOT=/opt/dynamorio

# =============================================================================
# 7. Working Directory
# =============================================================================
WORKDIR /workspace

# =============================================================================
# 7. Default Command
# =============================================================================
CMD ["/bin/bash"]
