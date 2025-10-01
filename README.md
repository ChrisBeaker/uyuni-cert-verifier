# uyuni-cert-verifier

This script inspects the podman secrets of a SUSE Multi Linux Manager (SMLM) installation to verify certificate chains and properties. These secrets (certificates) will be used inside the SMLM containers.

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

Nodes:
This has only been tested on SMLM 5.1 or highe

If sub CAs are used, it is expected that the root CA and all sub CAs are in the uyuni-ca or uyuni-db-ca secrets. 
This can happen in two ways during installation:
- The mgradm install podman parameters --ssl-ca-intermediate and/or --ssl-db-ca-intermediate were used to provide the sub CAs.
- Alternatively, only the --ssl-ca-root or --ssl-db-ca-root parameters were used, but the file provided for these parameters
  was already contained the root CA and all sub CAs combined into a single file.



