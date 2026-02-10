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

# Normalize package filenames to match expected patterns (no version)
normalize_package_names() {
    local tmp_dir="./tmp"
    local renamed=0

    echo "Normalizing package filenames..."

    # Function to rename files to standard names without version
    rename_to_standard() {
        local pattern="$1"
        local standard_name="$2"
        local standard_file="${tmp_dir}/${standard_name}.tar.gz"

        # Skip if standard file already exists
        if [[ -f "$standard_file" ]]; then
            return 0
        fi

        # Find files matching the pattern
        for file in "${tmp_dir}"/${pattern}*.tar.gz; do
            # Check if file exists (glob might not match anything)
            [[ -f "$file" ]] || continue

            local basename=$(basename "$file")
            # Skip if already has standard name
            if [[ "$basename" == "${standard_name}.tar.gz" ]]; then
                return 0
            fi

            # Rename to standard name
            mv "$file" "$standard_file"
            echo "   Renamed: $basename → ${standard_name}.tar.gz"
            ((renamed++))
            break  # Only rename first match for each pattern
        done
    }

    # Rename packages to standard names (without version)
    rename_to_standard "go" "go"
    rename_to_standard "DynamoRIO" "DynamoRIO"
    rename_to_standard "routinator" "routinator"
    rename_to_standard "cfrpki" "cfrpki"
    rename_to_standard "fort" "fort"
    rename_to_standard "rpki-client" "rpki-client"

    if [ $renamed -eq 0 ]; then
        echo "   All package names already normalized"
    else
        echo "   ✓ Renamed $renamed package(s)"
    fi
    echo ""
}

# Check which packages are missing (returns array of missing package names)
check_missing_packages() {
    local tmp_dir="./tmp"
    local missing=()

    # Check Go
    if ! ls "${tmp_dir}"/go*.tar.gz 2>/dev/null | grep -q .; then
        missing+=("go")
    fi

    # Check DynamoRIO
    if ! ls "${tmp_dir}"/DynamoRIO*.tar.gz 2>/dev/null | grep -q .; then
        missing+=("DynamoRIO")
    fi

    # Check Routinator
    if ! ls "${tmp_dir}"/routinator*.tar.gz 2>/dev/null | grep -q .; then
        missing+=("routinator")
    fi

    # Check FORT Validator
    if ! ls "${tmp_dir}"/fort*.tar.gz 2>/dev/null | grep -q .; then
        missing+=("fort")
    fi

    # Check rpki-client
    if ! ls "${tmp_dir}"/rpki-client*.tar.gz 2>/dev/null | grep -q .; then
        missing+=("rpki-client")
    fi

    # Check OctoRPKI (cfrpki)
    if ! ls "${tmp_dir}"/cfrpki*.tar.gz 2>/dev/null | grep -q .; then
        missing+=("cfrpki")
    fi

    echo "${missing[@]}"
}

# Download missing packages
download_missing_packages() {
    local tmp_dir="./tmp"
    local missing=($(check_missing_packages))

    echo "Checking required packages in ${tmp_dir}/..."

    # Define packages with URL and standard filename (no version)
    declare -A packages=(
        ["go_url"]="https://go.dev/dl/go1.25.7.linux-amd64.tar.gz"
        ["go_file"]="go.tar.gz"
        ["DynamoRIO_url"]="https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-11.90.20482/DynamoRIO-Linux-11.90.20482.tar.gz"
        ["DynamoRIO_file"]="DynamoRIO.tar.gz"
        ["routinator_url"]="https://github.com/NLnetLabs/routinator/archive/refs/tags/v0.15.1.tar.gz"
        ["routinator_file"]="routinator.tar.gz"
        ["fort_url"]="https://github.com/NICMx/FORT-validator/releases/download/1.6.7/fort-1.6.7.tar.gz"
        ["fort_file"]="fort.tar.gz"
        ["rpki-client_url"]="https://github.com/rpki-client/rpki-client-portable/releases/download/9.6/rpki-client-9.6.tar.gz"
        ["rpki-client_file"]="rpki-client.tar.gz"
        ["cfrpki_url"]="https://github.com/cloudflare/cfrpki/archive/refs/tags/v1.5.10.tar.gz"
        ["cfrpki_file"]="cfrpki.tar.gz"
    )

    if [ ${#missing[@]} -ne 0 ]; then
        echo "⚠️  Missing packages detected:"
        for pkg in "${missing[@]}"; do
            echo "   - $pkg"
        done
        echo ""
        echo "📥 Automatically downloading missing packages..."

        # Check if wget or curl is available
        if command -v wget &>/dev/null; then
            downloader="wget"
        elif command -v curl &>/dev/null; then
            downloader="curl"
        else
            echo "❌ Error: Neither wget nor curl is available."
            echo "Please install one of them to proceed with automatic downloads."
            exit 1
        fi

        cd "${tmp_dir}"

        for pkg in "${missing[@]}"; do
            local url="${packages[${pkg}_url]}"
            local filename="${packages[${pkg}_file]}"
            echo "   Downloading: $filename"

            if [ "$downloader" = "wget" ]; then
                wget -q --show-progress -O "$filename" "$url" || {
                    echo "❌ Failed to download: $filename"
                    cd ..
                    exit 1
                }
            else
                curl -L -o "$filename" "$url" || {
                    echo "❌ Failed to download: $filename"
                    cd ..
                    exit 1
                }
            fi
        done

        cd ..
        echo "✓ All packages downloaded successfully"
    else
        echo "✓ All required packages found"
    fi
    echo ""
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
    download_missing_packages
    normalize_package_names
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
