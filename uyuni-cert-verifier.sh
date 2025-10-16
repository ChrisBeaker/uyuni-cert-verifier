#!/bin/bash

# This script inspects podman secrets of a SUSE Multi Linux Manager installation to verify certificate chains and properties.
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
if ! command -v awk &> /dev/null; then
    echo "Error: awk command not found. Please install it." >&2
    exit 1
fi
if [ ! -f "$SECRETS_DB_FILE" ]; then
    echo "Error: The secrets database file was not found at $SECRETS_DB_FILE" >&2
    exit 1
fi

# --- Initialization ---
DEBUG_MODE=0
if [[ "$1" == "--debug" ]]; then
    DEBUG_MODE=1
    echo "## Debug mode enabled."
fi

OVERALL_STATUS=0 # 0 for success, 1 for failure
LEGACY_CA_STRUCTURE_DETECTED=0 # 0 for false, 1 for true
CA_BUNDLE_FILE=$(mktemp)
TEMP_DIR=$(mktemp -d)
# Ensure cleanup on exit
trap 'rm -f "$CA_BUNDLE_FILE"; rm -rf "$TEMP_DIR"' EXIT

# --- Helper Functions ---
debug_echo() {
    if [[ "$DEBUG_MODE" -eq 1 ]]; then
        echo "DEBUG: $1"
    fi
}

echo "## SUSE Multi Linux Manager Certificate Verifier - Generated on $(date)"
echo "## Phase 1: Finding and Verifying CA certificates..."

declare -A PROCESSED_SECRET_IDS # Array to track processed secret IDs to avoid redundant work
declare -A PROCESSED_CA_FINGERPRINTS # Array to track processed CA certificate fingerprints to avoid duplicates
# --- Pass 1: Collect All CA Certificates from All Secrets ---
CONTAINERS=$(podman ps -a --format "{{.Names}}")

for container in $CONTAINERS; do
    debug_echo "Scanning container '$container' for secrets..."
    secret_definitions=$(podman inspect "$container" --format '{{range .Config.CreateCommand}}{{.}}{{"\n"}}{{end}}' \
        | grep -A 1 -- '--secret' \
        | grep -v -- '--secret' \
        | grep -v 'type=env')

    if [ -z "$secret_definitions" ]; then
        continue
    fi

    while IFS= read -r line; do
        secret_name=$(echo "$line" | cut -d',' -f1)
        secret_id=$(podman secret inspect --format '{{.ID}}' "$secret_name" 2>/dev/null)
        
        if [ -z "$secret_id" ]; then
            debug_echo "Could not get ID for secret '$secret_name', skipping."
            continue
        fi

        if [[ -v "PROCESSED_SECRET_IDS[$secret_id]" ]]; then
            debug_echo "Secret '$secret_name' (ID: $secret_id) already processed, skipping."
            continue
        fi
        PROCESSED_SECRET_IDS[$secret_id]=1

        encoded_content=$(grep """$secret_id""" "$SECRETS_DB_FILE" | cut -d'"' -f4)
        secret_content=$(echo "$encoded_content" | base64 -d 2>/dev/null)

        # Process only if it's a certificate
        if echo "$secret_content" | grep -q -- '-----BEGIN CERTIFICATE-----'; then
            debug_echo "Found certificate(s) in secret '$secret_name'"
            
            CERT_DIR=$(mktemp -d -p "$TEMP_DIR")
            (cd "$CERT_DIR" && awk '/-----BEGIN CERTIFICATE-----/ { out="cert-" ++c ".pem" } out { print > out }' <<< "$secret_content")

            for cert_file in "$CERT_DIR"/cert-*.pem; do
                [ -f "$cert_file" ] || continue
                cert_content_single=$(cat "$cert_file")

                # Check if the cert is a CA
                if echo "$cert_content_single" | openssl x509 -noout -text | grep -q "CA:TRUE"; then
                    CA_CN=$(echo "$cert_content_single" | openssl x509 -noout -subject -nameopt multiline | sed -n 's/.*commonName.*= //p')

                    # Determine if it's a Root or Intermediate CA
                    SUBJECT_HASH=$(echo "$cert_content_single" | openssl x509 -noout -subject_hash 2>/dev/null)
                    ISSUER_HASH=$(echo "$cert_content_single" | openssl x509 -noout -issuer_hash 2>/dev/null)
                    CA_TYPE="Intermediate CA"
                    if [[ -n "$SUBJECT_HASH" && "$SUBJECT_HASH" == "$ISSUER_HASH" ]]; then
                        CA_TYPE="Root CA"
                    fi

                    echo "Found $CA_TYPE: '$CA_CN' in secret '$secret_name'."

                    # Now, handle adding to the bundle with de-duplication
                    FINGERPRINT=$(echo "$cert_content_single" | openssl x509 -noout -fingerprint -sha256)
                    if [[ -v "PROCESSED_CA_FINGERPRINTS[$FINGERPRINT]" ]]; then
                        debug_echo "CA with fingerprint $FINGERPRINT already processed, not adding to bundle again."
                    else
                        echo "Adding '$CA_CN' to verification bundle."
                        PROCESSED_CA_FINGERPRINTS[$FINGERPRINT]=1
                        
                        # Add a newline if the bundle isn't empty
                        if [ -s "$CA_BUNDLE_FILE" ]; then
                            echo "" >> "$CA_BUNDLE_FILE"
                        fi
                        echo "$cert_content_single" >> "$CA_BUNDLE_FILE"
                    fi
                fi
            done
        fi
    done <<< "$secret_definitions"
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

    while IFS= read -r line; do
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

            # --- Legacy Structure Check ---
            # This check runs once per relevant secret to see if it contains both a root and an intermediate CA.
            if [[ "$secret_name" == "uyuni-ca" || "$secret_name" == "uyuni-db-ca" ]]; then
                ROOT_CA_COUNT=0
                INTERMEDIATE_CA_COUNT=0
                
                # We need to temporarily split the certs to analyze them
                CHECK_CERT_DIR=$(mktemp -d -p "$TEMP_DIR")
                (cd "$CHECK_CERT_DIR" && awk '/-----BEGIN CERTIFICATE-----/ { out="cert-" ++c ".pem" } out { print > out }' <<< "$secret_content")

                for check_cert_file in "$CHECK_CERT_DIR"/cert-*.pem; do
                    [ -f "$check_cert_file" ] || continue
                    
                    # Check if it's a CA certificate
                    if openssl x509 -in "$check_cert_file" -noout -text 2>/dev/null | grep -q "CA:TRUE"; then
                        SUBJECT_HASH=$(openssl x509 -in "$check_cert_file" -noout -subject_hash 2>/dev/null)
                        ISSUER_HASH=$(openssl x509 -in "$check_cert_file" -noout -issuer_hash 2>/dev/null)

                        if [[ -n "$SUBJECT_HASH" && "$SUBJECT_HASH" == "$ISSUER_HASH" ]]; then
                            ROOT_CA_COUNT=$((ROOT_CA_COUNT + 1))
                        else
                            INTERMEDIATE_CA_COUNT=$((INTERMEDIATE_CA_COUNT + 1))
                        fi
                    fi
                done

                if [[ "$ROOT_CA_COUNT" -gt 0 && "$INTERMEDIATE_CA_COUNT" -gt 0 ]]; then
                    LEGACY_CA_STRUCTURE_DETECTED=1
                    debug_echo "Legacy CA structure detected in secret '$secret_name'."
                fi
            fi
            
            echo "---"
            echo "Secret Name: $secret_name"
            echo "Target Path: $secret_path"

            # --- Certificate Splitting ---
            CERT_DIR=$(mktemp -d -p "$TEMP_DIR")
            (cd "$CERT_DIR" && awk '/-----BEGIN CERTIFICATE-----/ { out="cert-" ++c ".pem" } out { print > out }' <<< "$secret_content")

            CERT_COUNT=$(ls -1 "$CERT_DIR"/*.pem 2>/dev/null | wc -l)
            CERT_INDEX=0
            for cert_file in "$CERT_DIR"/cert-*.pem; do
                [ -f "$cert_file" ] || continue
                CERT_INDEX=$((CERT_INDEX + 1))

                # If there are multiple certs, add a small separator
                if [[ $CERT_COUNT -gt 1 && $CERT_INDEX -gt 1 ]]; then
                    echo "  ---"
                fi

                cert_content=$(cat "$cert_file")

                # --- 1. Display Essential Info ---
                echo "  - Subject  : $(echo "$cert_content" | openssl x509 -noout -subject -nameopt multiline | sed -n 's/.*commonName.*= //p')"
                echo "  - Issuer   : $(echo "$cert_content" | openssl x509 -noout -issuer -nameopt multiline | sed -n 's/.*commonName.*= //p')"
                echo "  - Valid From: $(echo "$cert_content" | openssl x509 -noout -startdate | cut -d= -f2)"
                echo "  - Valid Until: $(echo "$cert_content" | openssl x509 -noout -enddate | cut -d= -f2)"

                SANS=$(echo "$cert_content" | openssl x509 -noout -ext subjectAltName 2>/dev/null)
                if [[ -n "$SANS" ]]; then
                    echo "  - SANs     : ${SANS//DNS:/ }"
                fi

                # --- 2. Perform Validation ---
                # Check if the cert is a CA itself by checking Basic Constraints
                if echo "$cert_content" | openssl x509 -noout -text | grep -q "CA:TRUE"; then
                    echo "  - Type     : CA Certificate"
                else
                    echo "  - Type     : Server/Client Certificate"
                    VALIDATION_RESULT=$(openssl verify -CAfile "$CA_BUNDLE_FILE" "$cert_file" 2>&1)
                    echo "  - Validation: $VALIDATION_RESULT"
                    # Update overall status if validation failed
                    if ! echo "$VALIDATION_RESULT" | grep -q "OK"; then
                        OVERALL_STATUS=1
                    fi
                fi

                # --- 3. Perform DB SAN Check ---
                if [[ "$secret_name" == "uyuni-db-cert" ]]; then
                    # Only perform this check on server/client certs, not on CAs
                    if ! echo "$cert_content" | openssl x509 -noout -text | grep -q "CA:TRUE"; then
                        SUBJECT_CN=$(echo "$cert_content" | openssl x509 -noout -subject -nameopt multiline | sed -n 's/.*commonName.*= //p')
                        if [[ -n "$SANS" && "$SANS" == *"DNS:reportdb"* && "$SANS" == *"DNS:db"* && "$SANS" == *"DNS:$SUBJECT_CN"* ]]; then
                            echo "  - DB SAN Check: OK"
                        else
                            echo "  - DB SAN Check: FAILED (Missing 'reportdb', 'db', or FQDN '$SUBJECT_CN' in SANs)"
                            OVERALL_STATUS=1
                        fi
                    fi
                fi
            done
        fi
    done <<< "$secret_definitions"

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

if [[ "$LEGACY_CA_STRUCTURE_DETECTED" -eq 1 ]]; then
    echo
    echo "----------------------------------------------------------------------"
    echo "## Recommendation"
    echo "----------------------------------------------------------------------"
    echo "A legacy certificate structure was detected where a root CA and an"
    echo "intermediate CA were found together in 'uyuni-ca' or 'uyuni-db-ca'."
    echo
    echo "While this configuration is currently valid, the recommended structure is:"
    echo "  - Root CA only in 'uyuni-ca' and 'uyuni-db-ca' secrets."
    echo "  - Intermediate CA(s) bundled with the server certificate in the"
    echo "    'uyuni-cert' and 'uyuni-db-cert' secrets."
fi

echo
echo "## End of Report"
