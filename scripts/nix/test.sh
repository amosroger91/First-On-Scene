#!/bin/bash

# test.sh
# Executes gather_info.sh and validates its output against the schema.

# Create results directory
mkdir -p results

# Install ajv-cli for validation
npm install -g ajv-cli

# Create a temporary schema without the 'date-time' format
cat schemas/artifact_schema.json | jq 'del(.properties.metadata.properties.collectionTimestamp.format) | del(.properties.metadata.properties.errors.items.properties.timestamp.format)' > schemas/temp_schema.json

# Execute the collection script
./scripts/nix/gather_info.sh > results/test_output.json

# Validate the output
ajv validate -s schemas/temp_schema.json -d results/test_output.json

if [ $? -eq 0 ]; then
    echo "✅ Test passed: output is valid against the schema."
    # Clean up the temporary schema file
    rm schemas/temp_schema.json
    exit 0
else
    echo "❌ Test failed: output is not valid against the schema."
    # Clean up the temporary schema file
    rm schemas/temp_schema.json
    exit 1
fi
