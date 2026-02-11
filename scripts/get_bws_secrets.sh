#!/bin/bash

# This script is intended to be used as a Packer external data source.
# It reads a JSON object from stdin, which must contain a Bitwarden access_token.
# It requires the PROJECT_ID environment variable to be set to the Bitwarden project ID.
# It fetches secrets from the specified project and outputs them as a single JSON object.

INPUT=$(cat)

export BWS_ACCESS_TOKEN=$(echo "$INPUT" | jq -r '.access_token')
export BWS_PROJECT_ID=$(echo "$INPUT" | jq -r '.project_id')
if [ -z "$BWS_ACCESS_TOKEN" ]; then
    echo "Error: Failed to parse access_token" >&2
    exit 1
fi
if [ -z "$BWS_PROJECT_ID" ]; then
    echo "Error: Failed to parse project" >&2
    exit 1
fi

# This converts a list of secrets into a single JSON object: {"SECRET_NAME": "value", ...}
# The `// {}` ensures we output an empty JSON object if no secrets are found, instead of `null`.
bws secret list "${BWS_PROJECT_ID}" | jq 'reduce .[] as $item ({}; . + {($item.key): $item.value}) // {}'