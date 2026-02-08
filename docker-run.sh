#!/bin/bash
#
# Artifact Docker Helper Script
#
# Usage:
#   ./docker-run.sh                    # Start interactive shell
#   ./docker-run.sh <command>          # Run command in container
#
# Examples:
#   ./docker-run.sh
#   ./docker-run.sh python3 tools/batch_diversity_generator.py --num-repos 10
#   ./docker-run.sh python3 repo_structure_mutator.py --help
#

set -e

IMAGE_NAME="artifact:latest"
CONTAINER_NAME="artifact"

# Prepare environment directories
prepare_environment() {
    echo "Preparing environment directories..."

    # Create tmp directory for packages
    if [ ! -d "./tmp" ]; then
        mkdir -p tmp
        echo "✓ Created tmp/ directory"
    fi

    # Create rp_cache directories for RPKI validators
    if [ ! -d "./rp_cache" ]; then
        mkdir -p rp_cache/{fort_cache,octorpki_cache,routinator_cache,rpki-client_cache,rpki-client_output}
        echo "✓ Created rp_cache/ directories"
    fi

    echo ""
}

# Check required packages in tmp/
check_required_packages() {
    local tmp_dir="./tmp"
    local missing=()

    echo "Checking required packages in ${tmp_dir}/..."

    # Check Go
    if ! ls "${tmp_dir}"/go*.tar.gz 2>/dev/null | grep -q .; then
        missing+=("Go (go*.tar.gz)")
    fi

    # Check DynamoRIO
    if ! ls "${tmp_dir}"/DynamoRIO*.tar.gz 2>/dev/null | grep -q .; then
        missing+=("DynamoRIO (DynamoRIO*.tar.gz)")
    fi

    # Check Routinator
    if ! ls "${tmp_dir}"/routinator*.tar.gz 2>/dev/null | grep -q .; then
        missing+=("Routinator (routinator*.tar.gz)")
    fi

    # Check FORT Validator
    if ! ls "${tmp_dir}"/fort*.tar.gz 2>/dev/null | grep -q .; then
        missing+=("FORT (fort*.tar.gz)")
    fi

    # Check rpki-client
    if ! ls "${tmp_dir}"/rpki-client*.tar.gz 2>/dev/null | grep -q .; then
        missing+=("rpki-client (rpki-client*.tar.gz)")
    fi

    # Check OctoRPKI (cfrpki)
    if ! ls "${tmp_dir}"/cfrpki*.tar.gz 2>/dev/null | grep -q .; then
        missing+=("OctoRPKI (cfrpki*.tar.gz)")
    fi

    if [ ${#missing[@]} -ne 0 ]; then
        echo "❌ Error: Missing required packages:"
        for pkg in "${missing[@]}"; do
            echo "   - $pkg"
        done
        echo ""
        echo "Please download the required packages to ${tmp_dir}/:"
        echo ""
        echo "  cd ${tmp_dir}"
        echo "  wget https://go.dev/dl/go1.25.7.linux-amd64.tar.gz"
        echo "  wget https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-11.90.20482/DynamoRIO-Linux-11.90.20482.tar.gz"
        echo "  wget https://github.com/NLnetLabs/routinator/archive/refs/tags/v0.15.1.tar.gz"
        echo "  wget https://github.com/cloudflare/cfrpki/archive/refs/tags/v1.5.10.tar.gz"
        echo "  wget https://github.com/rpki-client/rpki-client-portable/releases/download/9.6/rpki-client-9.6.tar.gz"
        echo "  wget https://github.com/NICMx/FORT-validator/releases/download/1.6.7/fort-1.6.7.tar.gz"
        echo "  cd .."
        echo ""
        echo "Note: You can use different versions - the script will auto-detect them."
        echo ""
        exit 1
    fi

    echo "✓ All required packages found"
}

# Detect actual filenames in tmp/
detect_package_versions() {
    local tmp_dir="./tmp"

    GO_PKG=$(ls "${tmp_dir}"/go*.tar.gz 2>/dev/null | head -1 | xargs basename)
    DYNAMORIO_PKG=$(ls "${tmp_dir}"/DynamoRIO*.tar.gz 2>/dev/null | head -1 | xargs basename)
    ROUTINATOR_PKG=$(ls "${tmp_dir}"/routinator*.tar.gz 2>/dev/null | head -1 | xargs basename)
    FORT_PKG=$(ls "${tmp_dir}"/fort*.tar.gz 2>/dev/null | head -1 | xargs basename)
    RPKI_CLIENT_PKG=$(ls "${tmp_dir}"/rpki-client*.tar.gz 2>/dev/null | head -1 | xargs basename)
    CFRPKI_PKG=$(ls "${tmp_dir}"/cfrpki*.tar.gz 2>/dev/null | head -1 | xargs basename)

    export GO_PKG DYNAMORIO_PKG ROUTINATOR_PKG FORT_PKG RPKI_CLIENT_PKG CFRPKI_PKG

    echo "Detected package versions:"
    echo "  Go:          ${GO_PKG}"
    echo "  DynamoRIO:   ${DYNAMORIO_PKG}"
    echo "  Routinator:  ${ROUTINATOR_PKG}"
    echo "  FORT:        ${FORT_PKG}"
    echo "  rpki-client: ${RPKI_CLIENT_PKG}"
    echo "  OctoRPKI:    ${CFRPKI_PKG}"
}

# Build image if not exists
if ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    echo "Building Docker image: $IMAGE_NAME"
    prepare_environment
    check_required_packages
    detect_package_versions
    docker build -t "$IMAGE_NAME" \
        --build-arg GO_PKG="${GO_PKG}" \
        --build-arg DYNAMORIO_PKG="${DYNAMORIO_PKG}" \
        --build-arg ROUTINATOR_PKG="${ROUTINATOR_PKG}" \
        --build-arg FORT_PKG="${FORT_PKG}" \
        --build-arg RPKI_CLIENT_PKG="${RPKI_CLIENT_PKG}" \
        --build-arg CFRPKI_PKG="${CFRPKI_PKG}" \
        -f docker/Dockerfile .
else
    # Even if image exists, ensure environment directories are ready
    prepare_environment
fi

# Check if container is already running
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    # Remove existing container
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
fi

# Run container
if [ $# -eq 0 ]; then
    # Interactive shell
    echo "Starting Artifact container..."
    docker run -it --rm \
        --name "$CONTAINER_NAME" \
        -v "$(pwd):/workspace" \
        -e DR_ROOT=/opt/dynamorio \
        "$IMAGE_NAME" /bin/bash
else
    # Run command
    docker run --rm \
        --name "$CONTAINER_NAME" \
        -v "$(pwd):/workspace" \
        -e DR_ROOT=/opt/dynamorio \
        "$IMAGE_NAME" "$@"
fi
