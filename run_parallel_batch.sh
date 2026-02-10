#!/bin/bash
# Usage examples:
#   ./run_parallel_batch.sh --runs 5 --threads 3
#   ./run_parallel_batch.sh --runs 10 --threads 4 --num-repos 500 --timeout 30

# Default parameters
RUNS=5              # Number of batch runs
THREADS=3           # Number of parallel threads
NUM_REPOS=1000      # Number of repos per batch
TIMEOUT=60          # Timeout per repo (seconds)
DEPTH_RANGE="1 100" # Depth range
BRANCH_RANGE="1 2"  # Branch range
RUN_TIMEOUT=36000   # Timeout per batch run (seconds)
OUTPUT_DIR="output"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --runs)
            RUNS="$2"
            shift 2
            ;;
        --threads)
            THREADS="$2"
            shift 2
            ;;
        --num-repos)
            NUM_REPOS="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --depth-range)
            DEPTH_RANGE="$2 $3"
            shift 3
            ;;
        --branch-range)
            BRANCH_RANGE="$2 $3"
            shift 3
            ;;
        --run-timeout)
            RUN_TIMEOUT="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --keep-repos)
            KEEP_REPOS="--keep-repos"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --runs N              Number of batch runs (default: 5)"
            echo "  --threads N           Number of parallel threads (default: 3)"
            echo "  --num-repos N         Number of repos per batch (default: 1000)"
            echo "  --timeout N           Timeout per repo in seconds (default: 60)"
            echo "  --depth-range MIN MAX Depth range (default: 1 100)"
            echo "  --branch-range MIN MAX Branch range (default: 1 2)"
            echo "  --run-timeout N       Timeout per batch run in seconds (default: 7200)"
            echo "  --output-dir DIR      Output directory (default: output)"
            echo "  --keep-repos          Keep repository files"
            echo "  -h, --help            Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --runs 5 --threads 3"
            echo "  $0 --runs 10 --threads 4 --num-repos 500"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage"
            exit 1
            ;;
    esac
done

# Display configuration
echo "=========================================="
echo "Parallel Batch Execution Configuration"
echo "=========================================="
echo "Number of runs:     $RUNS"
echo "Parallel threads:   $THREADS"
echo "Repos per batch:    $NUM_REPOS"
echo "Depth range:        $DEPTH_RANGE"
echo "Branch range:       $BRANCH_RANGE"
echo "Timeout per repo:   ${TIMEOUT}s"
echo "Timeout per batch:  ${RUN_TIMEOUT}s"
echo "Output directory:   $OUTPUT_DIR"
echo "=========================================="
echo ""

# Execute Python script
python3 tools/run_parallel_batch.py \
    --runs "$RUNS" \
    --threads "$THREADS" \
    --num-repos "$NUM_REPOS" \
    --timeout "$TIMEOUT" \
    --depth-range $DEPTH_RANGE \
    --branch-range $BRANCH_RANGE \
    --run-timeout "$RUN_TIMEOUT" \
    --output-dir "$OUTPUT_DIR" \
    $KEEP_REPOS
