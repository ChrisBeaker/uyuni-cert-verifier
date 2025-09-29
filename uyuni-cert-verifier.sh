#!/bin/bash

# This script inspects podman secrets to verify certificate chains and properties.
#
# It performs the following steps:
# 1. Creates a temporary CA bundle file.
# 2. Pass 1: Iterates through all containers and their secrets to find certificates
#    acting as CAs (identified by name) and adds them to the CA bundle.
# 3. Pass 2: Iterates through all containers and secrets again to process
#    each certificate.
#    - It prints essential information (Subject, Issuer, Validity, SANs).
#    - It verifies server certificates against the generated CA bundle.
#    - It performs a specific SAN check for the database certificate.
# 4. Cleans up the temporary CA bundle file.

# --- Configuration ---
SECRETS_DB_FILE="/var/lib/containers/storage/secrets/filedriver/secretsdata.json"
CA_NAMES=("uyuni-ca" "uyuni-db-ca") # Names of secrets that are CAs

# --- Sanity Checks ---
if ! command -v openssl &> /dev/null; then
    echo "Error: openssl command not found. Please install it." >&2
    exit 1
fi
if [ ! -f "$SECRETS_DB_FILE" ]; then
    echo "Error: The secrets database file was not found at $SECRETS_DB_FILE" >&2
    exit 1
fi

# --- Initialization ---
OVERALL_STATUS=0 # 0 for success, 1 for failure
CA_BUNDLE_FILE=$(mktemp)
# Ensure cleanup on exit
trap 'rm -f "$CA_BUNDLE_FILE"' EXIT

echo "## SUSE Multi Linux Manager Certificate Verifier - Generated on $(date)"
echo "## Phase 1: Finding CA certificates..."

# --- Pass 1: Collect CA Certificates ---
CONTAINERS=$(podman ps -a --format "{{.Names}}")

for container in $CONTAINERS; do
    secret_definitions=$(podman inspect "$container" --format '''{{range .Config.CreateCommand}}{{.}}{{"\n"}}{{end}}''' \
        | grep -A 1 -- '--secret' \
        | grep -v -- '--secret' \
        | grep -v 'type=env')

    if [ -z "$secret_definitions" ]; then
        continue
    fi

    echo "$secret_definitions" | while IFS= read -r line; do
        secret_name=$(echo "$line" | cut -d',' -f1)
        
        for ca_name in "${CA_NAMES[@]}"; do
            if [[ "$secret_name" == "$ca_name" ]]; then
                echo "Found CA secret: '$secret_name' in container '$container'"
                secret_id=$(podman secret inspect --format '{{.ID}}' "$secret_name" 2>/dev/null)
                if [ -n "$secret_id" ]; then
                    encoded_content=$(grep """$secret_id""" "$SECRETS_DB_FILE" | cut -d'"' -f4)
                    decoded_content=$(echo "$encoded_content" | base64 -d 2>/dev/null)
                    # Append a newline just in case the cert file doesn't have one
                    echo -e "\n$decoded_content" >> "$CA_BUNDLE_FILE"
                fi
                # Break inner loop once matched
                break
            fi
        done
    done
done

echo "## Phase 2: Verifying all certificates..."

# --- Pass 2: Process All Certificates ---
declare -A PROCESSED_SECRETS # Use associative array to avoid reprocessing the same secret

for container in $CONTAINERS; do
    secret_definitions=$(podman inspect "$container" --format '''{{range .Config.CreateCommand}}{{.}}{{"\n"}}{{end}}''' \
        | grep -A 1 -- '--secret' \
        | grep -v -- '--secret' \
        | grep -v 'type=env')

    if [ -z "$secret_definitions" ]; then
        continue
    fi
    
    echo
    echo "======================================================================"
    echo "## Container: $container"
    echo "======================================================================"

    echo "$secret_definitions" | while IFS= read -r line; do
        secret_name=$(echo "$line" | cut -d',' -f1)
        secret_path=$(echo "$line" | sed -n 's/.*target=\(.*\)$/\1/p')

        # Avoid reprocessing a secret that's mounted multiple times
        if [[ -v "PROCESSED_SECRETS[$secret_name]" ]]; then
            echo "---"
            echo "Secret Name: $secret_name (already processed, skipping)"
            echo "Target Path: $secret_path"
            continue
        fi

        secret_id=$(podman secret inspect --format '{{.ID}}' "$secret_name" 2>/dev/null)
        if [ -z "$secret_id" ]; then
            continue
        fi

        encoded_content=$(grep """$secret_id""" "$SECRETS_DB_FILE" | cut -d'"' -f4)
        secret_content=$(echo "$encoded_content" | base64 -d 2>/dev/null)

        # Process only if it's a certificate
        if echo "$secret_content" | grep -q -- '-----BEGIN CERTIFICATE-----'; then
            PROCESSED_SECRETS[$secret_name]=1
            
            echo "---"
            echo "Secret Name: $secret_name"
            echo "Target Path: $secret_path"

            # --- 1. Display Essential Info ---
            echo "  - Subject  : $(echo "$secret_content" | openssl x509 -noout -subject -nameopt multiline | sed -n 's/.*commonName.*= //p')"
            echo "  - Issuer   : $(echo "$secret_content" | openssl x509 -noout -issuer -nameopt multiline | sed -n 's/.*commonName.*= //p')"
            echo "  - Valid From: $(echo "$secret_content" | openssl x509 -noout -startdate | cut -d= -f2)"
            echo "  - Valid Until: $(echo "$secret_content" | openssl x509 -noout -enddate | cut -d= -f2)"
            
            SANS=$(echo "$secret_content" | openssl x509 -noout -ext subjectAltName 2>/dev/null)
            if [[ -n "$SANS" ]]; then
                echo "  - SANs     : ${SANS//DNS:/ }"
            fi

            # --- 2. Perform Validation ---
            # Check if the cert is a CA itself by checking Basic Constraints
            if echo "$secret_content" | openssl x509 -noout -text | grep -q "CA:TRUE"; then
                echo "  - Type     : CA Certificate"
            else
                echo "  - Type     : Server/Client Certificate"
                # Create a temporary file for the current certificate to verify
                CURRENT_CERT_FILE=$(mktemp)
                echo "$secret_content" > "$CURRENT_CERT_FILE"
                VALIDATION_RESULT=$(openssl verify -CAfile "$CA_BUNDLE_FILE" "$CURRENT_CERT_FILE" 2>&1)
                rm "$CURRENT_CERT_FILE"
                echo "  - Validation: $VALIDATION_RESULT"
                # Update overall status if validation failed
                if ! echo "$VALIDATION_RESULT" | grep -q "OK"; then
                    OVERALL_STATUS=1
                fi
            fi

            # --- 3. Perform DB SAN Check ---
            if [[ "$secret_name" == "uyuni-db-cert" ]]; then
                SUBJECT_CN=$(echo "$secret_content" | openssl x509 -noout -subject -nameopt multiline | sed -n 's/.*commonName.*= //p')
                if [[ -n "$SANS" && "$SANS" == *"DNS:reportdb"* && "$SANS" == *"DNS:db"* && "$SANS" == *"DNS:$SUBJECT_CN"* ]]; then
                    echo "  - DB SAN Check: OK"
                else
                    echo "  - DB SAN Check: FAILED (Missing 'reportdb', 'db', or FQDN '$SUBJECT_CN')"
                    OVERALL_STATUS=1
                fi
            fi
        fi
    done
done

# --- Final Summary ---
echo
echo "======================================================================"
echo "## Overall Status"
echo "======================================================================"
if [[ "$OVERALL_STATUS" -eq 0 ]]; then
    echo "All tests passed."
else
    echo "One or more tests failed. Please review the report."
fi

echo
echo "## End of Report"
