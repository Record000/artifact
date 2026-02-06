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

# Install Go 1.25.7 (from tmp/)
COPY tmp/go1.25.7.linux-amd64.tar.gz /tmp/
RUN tar -C /usr/local -xzf /tmp/go1.25.7.linux-amd64.tar.gz && \
    rm /tmp/go1.25.7.linux-amd64.tar.gz && \
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
ENV DR_ROOT=/opt/dynamorio

COPY tmp/DynamoRIO-Linux-11.90.20482.tar.gz /tmp/
RUN cd /tmp && \
    tar xzf DynamoRIO-Linux-11.90.20482.tar.gz && \
    mv DynamoRIO-Linux-11.90.20482 ${DR_ROOT} && \
    rm DynamoRIO-Linux-11.90.20482.tar.gz

ENV PATH="${DR_ROOT}/bin64:${PATH}"

# =============================================================================
# 4. RPKI Validators (build from source in tmp/)
# =============================================================================

# Copy all source tarballs from tmp/
COPY tmp/routinator-0.14.2.tar.gz /tmp/
COPY tmp/fort-1.6.7.tar.gz /tmp/
COPY tmp/rpki-client-9.6.tar.gz /tmp/
COPY tmp/cfrpki-1.5.10.tar.gz /tmp/

# Store validators in /opt/rp-validators (outside /workspace to avoid volume mount overlap)
RUN mkdir -p /opt/rp-validators

# --- Routinator 0.14.2 ---
RUN cd /tmp && \
    tar xzf routinator-0.14.2.tar.gz && \
    cd routinator-0.14.2 && \
    cargo build --release && \
    cp target/release/routinator /opt/rp-validators/ && \
    cd / && rm -rf /tmp/routinator-0.14.2 routinator-0.14.2.tar.gz

# --- FORT Validator 1.6.7 ---
RUN cd /tmp && \
    tar xzf fort-1.6.7.tar.gz && \
    cd fort-1.6.7 && \
    ./configure && \
    make -j$(nproc) && \
    cp src/fort /opt/rp-validators/ && \
    cd / && rm -rf /tmp/fort-1.6.7 fort-1.6.7.tar.gz

# --- rpki-client 9.6 ---
RUN cd /tmp && \
    tar xzf rpki-client-9.6.tar.gz && \
    cd rpki-client-9.6 && \
    ./configure --with-libtls=libretls && \
    make -j$(nproc) && \
    cp src/rpki-client /opt/rp-validators/ && \
    cd / && rm -rf /tmp/rpki-client-9.6 rpki-client-9.6.tar.gz

# --- OctoRPKI v1.5.10 (with patches) ---
COPY docker/octorpki-rsync.patch /tmp/octorpki-rsync.patch
RUN cd /tmp && \
    tar xzf cfrpki-1.5.10.tar.gz && \
    cd cfrpki-1.5.10 && \
    patch -p1 < /tmp/octorpki-rsync.patch && \
    cd cmd/octorpki && \
    go build -o /opt/rp-validators/octorpki . && \
    cd / && rm -rf /tmp/cfrpki-1.5.10 /tmp/octorpki-rsync.patch cfrpki-1.5.10.tar.gz

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
