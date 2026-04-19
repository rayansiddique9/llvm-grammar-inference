#!/bin/bash
# Wrapper for tiny.instrumented to accept filename argument
# 
# MIMID's grammar-miner expects: ./executable <input_file>
# But tiny.instrumented:
#   1. Reads from stdin (not filename argument)
#   2. Is a Linux binary (needs Docker on macOS)
# 
# This wrapper bridges both gaps

if [ $# -eq 0 ]; then
    echo "Usage: $0 <input_file>" >&2
    exit 1
fi

INPUT_FILE="$1"

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' not found" >&2
    exit 1
fi

# Get absolute path for Docker mount
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ABS_INPUT_FILE="$SCRIPT_DIR/$INPUT_FILE"

# Run tiny.instrumented inside Docker with input redirected from file
docker run --rm --platform linux/amd64 \
    -v "$SCRIPT_DIR:/workdir" \
    -w /workdir \
    trailofbits/polytracker \
    bash -c "./tiny.instrumented < '$INPUT_FILE'" 2>/dev/null

# Exit with same status as the instrumented binary
exit $?