# uyuni-cert-verifier

This script inspects podman secrets of a SUSE Multi Linux Manager installation to verify certificate chains and properties.

It performs the following steps:
1. Creates a temporary CA bundle file.
2. Pass 1: Iterates through all containers and their secrets to find certificates
   acting as CAs (identified by name) and adds them to the CA bundle.
3. Pass 2: Iterates through all containers and secrets again to process
   each certificate.
   - It prints essential information (Subject, Issuer, Validity, SANs).
   - It verifies server certificates against the generated CA bundle.
   - It performs a specific SAN check for the database certificate.
4. Cleans up the temporary CA bundle file.

Node:

Currently only tested on SMLM >= 5.1


