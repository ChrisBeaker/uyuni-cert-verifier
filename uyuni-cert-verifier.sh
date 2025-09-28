#!/bin/bash

# --- Configuration ---
SECRETS_DB_FILE="/var/lib/containers/storage/secrets/filedriver/secretsdata.json"

# --- Sanity Check ---
if [ ! -f "$SECRETS_DB_FILE" ]; then
    echo "Error: The secrets database file was not found at $SECRETS_DB_FILE" >&2
    exit 1
fi

echo "## Podman Secret Report - Generated on $(date)"

# Loop through all containers
for container in $(podman ps -a --format "{{.Names}}"); do
    
    secret_definitions=$(podman inspect "$container" --format '{{range .Config.CreateCommand}}{{.}}{{"\n"}}{{end}}' \
        | grep -A 1 -- '--secret' \
        | grep -v -- '--secret' \
        | grep -v 'type=env')

    if [ -n "$secret_definitions" ]; then
        echo
        echo "======================================================================"
        echo "## Container: $container"
        echo "======================================================================"

        echo "$secret_definitions" | while IFS= read -r line; do
            
            secret_name=$(echo "$line" | cut -d',' -f1)
            secret_path=$(echo "$line" | sed -n 's/.*target=\(.*\)$/\1/p')
            
            # --- This is the changed line ---
            # Removed '(index . 0)' to match the behavior of your podman version.
            secret_id=$(podman secret inspect --format '{{.ID}}' "$secret_name" 2>/dev/null)

            if [ -z "$secret_id" ]; then
                secret_content="Error: Could not find ID for secret '$secret_name'."
            else
                encoded_content=$(grep "\"$secret_id\"" "$SECRETS_DB_FILE" | cut -d'"' -f4)
                secret_content=$(echo "$encoded_content" | base64 -d 2>/dev/null)
            fi

            # --- Print the Structured Output ---
            echo "---"
            echo "Secret Name: $secret_name"
            echo "Target Path: $secret_path"
            echo "Content:"
            if echo "$secret_content" | grep -q -- "-----BEGIN CERTIFICATE-----"; then
                echo "$secret_content" | openssl x509 -text -noout 2>/dev/null
            fi
            echo "$secret_content"
        done
    fi
done

echo
echo "## End of Report"
