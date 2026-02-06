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

# Build image if not exists
if ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    echo "Building Docker image: $IMAGE_NAME"
    docker build -t "$IMAGE_NAME" -f docker/Dockerfile .
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
