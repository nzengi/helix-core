#!/bin/bash

# Exit on error
set -e
set -x  # Debug mode

# Configuration
GENESIS_PORT=8000
VALIDATOR_COUNT=3
RELEASE_MODE=false
LOG_DIR="logs"
DATA_DIR="data"

# Create necessary directories
mkdir -p $LOG_DIR
mkdir -p $DATA_DIR

# Function to check if port is available
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null ; then
        echo "Port $1 is already in use. Please free up the port and try again."
        exit 1
    fi
}

# Function to cleanup on exit
cleanup() {
    echo "🧹 Cleaning up..."
    kill $(jobs -p) 2>/dev/null || true
    exit 0
}

# Set up cleanup trap
trap cleanup SIGINT SIGTERM EXIT

echo "🚀 Starting HelixChain TestNet"

# Check if ports are available
check_port $GENESIS_PORT
for i in $(seq 1 $VALIDATOR_COUNT); do
    check_port $((GENESIS_PORT + i))
done

# Build in release mode if specified
if [ "$RELEASE_MODE" = true ]; then
    echo "📦 Building in release mode..."
    cargo build --release
    BINARY_PATH="./target/release/helix-chain"
else
    BINARY_PATH="./target/debug/helix-chain"
fi

# Start genesis node
echo "🌍 Starting Genesis Node..."
$BINARY_PATH --example genesis_setup \
    --port $GENESIS_PORT \
    --data-dir "$DATA_DIR/genesis" \
    --log-file "$LOG_DIR/genesis.log" &
GENESIS_PID=$!

sleep 2

# Start validator nodes
for i in $(seq 1 $VALIDATOR_COUNT); do
    PORT=$((GENESIS_PORT + i))
    echo "Starting Validator Node $i on port $PORT..."
    HELIX_NODE_ID="validator_$i" \
    HELIX_PORT=$PORT \
    $BINARY_PATH \
        --data-dir "$DATA_DIR/validator_$i" \
        --log-file "$LOG_DIR/validator_$i.log" &
    sleep 1
done

echo "✅ TestNet started successfully!"
echo "📊 Genesis Node API: http://localhost:$GENESIS_PORT/api/v1/status"
echo "📝 Logs available in $LOG_DIR directory"
echo "💾 Data stored in $DATA_DIR directory"

# Wait for genesis node
wait $GENESIS_PID
```
