package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	secretsDBFile = "/var/lib/containers/storage/secrets/filedriver/secretsdata.json"
)

var debugMode bool

func debugf(format string, args ...interface{}) {
	if debugMode {
		log.Printf("DEBUG: "+format, args...)
	}
}

func main() {
	flag.BoolVar(&debugMode, "debug", false, "Enable debug logging")
	flag.Parse()

	fmt.Printf("## SUSE Multi Linux Manager Certificate Verifier - Generated on %s\n", time.Now().Format(time.RFC1123))

	// --- Sanity Checks ---
	if _, err := exec.LookPath("podman"); err != nil {
		log.Fatalf("Error: podman command not found. Please install it and ensure it's in your PATH.")
	}
	if _, err := os.Stat(secretsDBFile); os.IsNotExist(err) {
		log.Fatalf("Error: The secrets database file was not found at %s", secretsDBFile)
	}

	containers, err := getPodmanContainers()
	if err != nil {
		log.Fatalf("Failed to get Podman containers: %v", err)
	}

	if len(containers) == 0 {
		fmt.Println("No containers found.")
		return
	}
	debugf("Found %d containers to inspect: %v", len(containers), containers)

	// --- Pass 1: Collect all CA certificates ---
	fmt.Println("\n## Phase 1: Finding and Verifying CA certificates...")
	caPool := x509.NewCertPool()
	processedSecretsPass1 := make(map[string]bool)

	for _, container := range containers {
		debugf("Scanning container '%s' for secrets...", container)
		secretDefs, err := getSecretDefinitions(container)
		if err != nil {
			debugf("Could not get secret definitions for %s: %v", container, err)
			continue
		}

		for _, secretDef := range secretDefs {
			secretName := parseSecretName(secretDef)
			secretID, err := getSecretID(secretName)
			if err != nil {
				debugf("Could not get ID for secret '%s', skipping.", secretName)
				continue
			}
			if processedSecretsPass1[secretID] {
				debugf("Secret '%s' (ID: %s) already processed in pass 1, skipping.", secretName, secretID)
				continue
			}
			processedSecretsPass1[secretID] = true

			content, err := getSecretContent(secretID)
			if err != nil {
				debugf("Could not get content for secret %s: %v", secretName, err)
				continue
			}

			certs := parseCertificates(content)
			for _, cert := range certs {
				if cert.IsCA {
					caPool.AddCert(cert)
					if isRootCA(cert) {
						fmt.Printf("Found Root CA: '%s' in secret '%s'. Adding to verification bundle.\n", cert.Subject.CommonName, secretName)
					} else {
						fmt.Printf("Found Intermediate CA: '%s' in secret '%s'. Adding to verification bundle.\n", cert.Subject.CommonName, secretName)
					}
				}
			}
		}
	}

	// --- Pass 2: Verify all certificates ---
	fmt.Println("\n## Phase 2: Verifying all certificates...")
	overallSuccess := true
	legacyCAStructureDetected := false
	processedSecretsPass2 := make(map[string]bool)

	for _, container := range containers {
		fmt.Printf("\n========================================================================\n")
		fmt.Printf("## Container: %s\n", container)
		fmt.Printf("========================================================================\n")

		secretDefs, _ := getSecretDefinitions(container)
		for _, secretDef := range secretDefs {
			secretName := parseSecretName(secretDef)
			secretPath := parseSecretPath(secretDef)

			secretID, err := getSecretID(secretName)
			if err != nil {
				continue // Already logged in pass 1
			}

			if processedSecretsPass2[secretID] {
				fmt.Printf("\n--- Secret Name: %s (already processed, skipping) ---\n", secretName)
				fmt.Printf("Target Path: %s\n", secretPath)
				continue
			}
			processedSecretsPass2[secretID] = true

			content, err := getSecretContent(secretID)
			if err != nil {
				continue // Already logged in pass 1
			}

			certs := parseCertificates(content)
			if len(certs) == 0 {
				continue
			}

			// Legacy Structure Check
			if secretName == "uyuni-ca" || secretName == "uyuni-db-ca" {
				if detectLegacyStructure(certs) {
					legacyCAStructureDetected = true
					debugf("Legacy CA structure detected in secret '%s'.", secretName)
				}
			}

			fmt.Printf("\n--- Secret Name: %s ---\n", secretName)
			fmt.Printf("Target Path: %s\n", secretPath)

			for i, cert := range certs {
				if i > 0 {
					fmt.Println("  ---")
				}
				printCertInfo(cert)

				if cert.IsCA {
					fmt.Println("  - Type     : CA Certificate")
				} else {
					fmt.Println("  - Type     : Server/Client Certificate")
					intermediatePool := x509.NewCertPool()
					// When verifying a server cert, the intermediates are expected to be in the same secret.
					for _, c := range certs {
						if c.IsCA && !isRootCA(c) {
							intermediatePool.AddCert(c)
						}
					}

					opts := x509.VerifyOptions{
						Roots:         caPool,
						Intermediates: intermediatePool,
						KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
					}
					if _, err := cert.Verify(opts); err != nil {
						fmt.Printf("  - Validation: FAILED (%v)\n", err)
						overallSuccess = false
					} else {
						fmt.Println("  - Validation: OK")
					}
				}

				if secretName == "uyuni-db-cert" && !cert.IsCA {
					if checkDbSan(cert) {
						fmt.Println("  - DB SAN Check: OK")
					} else {
						fmt.Printf("  - DB SAN Check: FAILED (Missing 'reportdb', 'db', or FQDN '%s' in SANs)\n", cert.Subject.CommonName)
						overallSuccess = false
					}
				}
			}
		}
	}

	// --- Final Summary ---
	fmt.Println("\n========================================================================")
	fmt.Println("## Overall Status")
	fmt.Println("========================================================================")
	if overallSuccess {
		fmt.Println("All tests passed.")
	} else {
		fmt.Println("One or more tests failed. Please review the report.")
	}

	if legacyCAStructureDetected {
		fmt.Println("\n------------------------------------------------------------------------")
		fmt.Println("## Recommendation")
		fmt.Println("------------------------------------------------------------------------")
		fmt.Println("A legacy certificate structure was detected where a root CA and an")
		fmt.Println("intermediate CA were found together in 'uyuni-ca' or 'uyuni-db-ca'.")
		fmt.Println()
		fmt.Println("While this configuration is currently valid, the recommended structure is:")
		fmt.Println("  - Root CA only in 'uyuni-ca' and 'uyuni-db-ca' secrets.")
		fmt.Println("  - Intermediate CA(s) bundled with the server certificate in the")
		fmt.Println("    'uyuni-cert' and 'uyuni-db-cert' secrets.")
	}
	fmt.Println("\n## End of Report")
}

func printCertInfo(cert *x509.Certificate) {
	fmt.Printf("  - Subject  : %s\n", cert.Subject.CommonName)
	fmt.Printf("  - Issuer   : %s\n", cert.Issuer.CommonName)
	fmt.Printf("  - Valid From: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("  - Valid Until: %s\n", cert.NotAfter.Format(time.RFC3339))
	if len(cert.DNSNames) > 0 {
		fmt.Printf("  - SANs     : %s\n", strings.Join(cert.DNSNames, " "))
	}
}

func checkDbSan(cert *x509.Certificate) bool {
	hasReportDB := false
	hasDB := false
	hasCN := false
	for _, san := range cert.DNSNames {
		if san == "reportdb" {
			hasReportDB = true
		}
		if san == "db" {
			hasDB = true
		}
		if san == cert.Subject.CommonName {
			hasCN = true
		}
	}
	return hasReportDB && hasDB && hasCN
}

func parseCertificates(pemData string) []*x509.Certificate {
	var certs []*x509.Certificate
	data := []byte(pemData)
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, cert)
			} else {
				debugf("Failed to parse certificate: %v", err)
			}
		}
	}
	return certs
}

func getSecretContent(secretID string) (string, error) {
	file, err := os.ReadFile(secretsDBFile)
	if err != nil {
		return "", fmt.Errorf("could not read secrets db file: %w", err)
	}

	var allSecrets map[string]string
	if err := json.Unmarshal(file, &allSecrets); err != nil {
		return "", fmt.Errorf("could not parse secrets db json: %w", err)
	}

	secretData, ok := allSecrets[secretID]
	if !ok {
		return "", fmt.Errorf("secret ID %s not found in secrets db", secretID)
	}

	decoded, err := base64.StdEncoding.DecodeString(secretData)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode secret data: %w", err)
	}

	return string(decoded), nil
}

func getPodmanContainers() ([]string, error) {
	cmd := exec.Command("podman", "ps", "-a", "--format", "{{.Names}}")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("running podman ps: %w, stderr: %s", err, stderr.String())
	}

	output := strings.TrimSpace(out.String())
	if output == "" {
		return []string{}, nil
	}

	return strings.Split(output, "\n"), nil
}

func getSecretDefinitions(containerName string) ([]string, error) {
	cmd := exec.Command("podman", "inspect", containerName, "--format", "{{json .Config.CreateCommand}}")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("running podman inspect for %s: %w, stderr: %s", containerName, err, stderr.String())
	}

	var createCommand []string
	if err := json.Unmarshal(out.Bytes(), &createCommand); err != nil {
		return nil, fmt.Errorf("could not parse podman inspect json: %w", err)
	}

	var secretDefs []string
	for i, arg := range createCommand {
		var def string
		if arg == "--secret" {
			if i+1 < len(createCommand) {
				def = createCommand[i+1]
			}
		} else if strings.HasPrefix(arg, "--secret=") {
			def = strings.TrimPrefix(arg, "--secret=")
		}

		if def != "" && !strings.Contains(def, "type=env") {
			secretDefs = append(secretDefs, def)
		}
	}
	debugf("Found %d secret definitions for container %s", len(secretDefs), containerName)
	return secretDefs, nil
}

func parseSecretName(secretDef string) string {
	parts := strings.Split(secretDef, ",")
	return parts[0]
}

func parseSecretPath(secretDef string) string {
	parts := strings.Split(secretDef, ",")
	for _, part := range parts {
		if strings.HasPrefix(part, "target=") {
			return strings.TrimPrefix(part, "target=")
		}
	}
	return ""
}

func getSecretID(secretName string) (string, error) {
	cmd := exec.Command("podman", "secret", "inspect", "--format", "{{.ID}}", secretName)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("running podman secret inspect for %s: %w, stderr: %s", secretName, err, stderr.String())
	}

	return strings.TrimSpace(out.String()), nil
}

func isRootCA(cert *x509.Certificate) bool {
	// A root CA is self-signed.
	return cert.IsCA && cert.Subject.CommonName == cert.Issuer.CommonName && bytes.Equal(cert.SubjectKeyId, cert.AuthorityKeyId)
}

func detectLegacyStructure(certs []*x509.Certificate) bool {
	hasRoot := false
	hasIntermediate := false
	for _, cert := range certs {
		if !cert.IsCA {
			continue
		}
		if isRootCA(cert) {
			hasRoot = true
		} else {
			hasIntermediate = true
		}
	}
	return hasRoot && hasIntermediate
}
