
```bash
#!/bin/bash

echo "🚀 Starting HelixChain TestNet"

# Genesis node
cargo run --example genesis_setup &
GENESIS_PID=$!

sleep 2

# Validator nodes
for i in {1..3}; do
    echo "Starting Validator Node $i..."
    HELIX_NODE_ID="validator_$i" \
    HELIX_PORT=$((8000 + i)) \
    cargo run &
    sleep 1
done

echo "✅ TestNet started with Genesis + 3 Validators"
echo "📊 Access API: http://localhost:8001/api/v1/status"

wait $GENESIS_PID
```
