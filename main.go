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

	fmt.Println("## SUSE Multi Linux Manager Certificate Verifier")

	containers, err := getPodmanContainers()
	if err != nil {
		log.Fatalf("Failed to get Podman containers: %v", err)
	}

	if len(containers) == 0 {
		fmt.Println("No containers found.")
		return
	}
	fmt.Printf("Found %d containers to inspect...\n", len(containers))

	// --- Pass 1: Collect all CA certificates ---
	fmt.Println("\n## Phase 1: Finding and Verifying CA certificates...")
	caPool := x509.NewCertPool()
	processedSecretsPass1 := make(map[string]bool)

	for _, container := range containers {
		secretDefs, _ := getSecretDefinitions(container)
		for _, secretDef := range secretDefs {
			secretName := parseSecretName(secretDef)
			secretID, err := getSecretID(secretName)
			if err != nil {
				continue
			}
			if processedSecretsPass1[secretID] {
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
					fmt.Printf("Found CA: '%s' in secret '%s'. Adding to verification bundle.\n", cert.Subject.CommonName, secretName)
				}
			}
		}
	}

	// --- Pass 2: Verify all certificates ---
	fmt.Println("\n## Phase 2: Verifying all certificates...")
	overallSuccess := true
	processedSecretsPass2 := make(map[string]bool)

	for _, container := range containers {
		fmt.Printf("\n======================================================================\n")
		fmt.Printf("## Container: %s\n", container)
		fmt.Printf("======================================================================\n")

		secretDefs, _ := getSecretDefinitions(container)
		for _, secretDef := range secretDefs {
			secretName := parseSecretName(secretDef)
			secretID, err := getSecretID(secretName)
			if err != nil {
				continue
			}

			if processedSecretsPass2[secretID] {
				continue
			}
			processedSecretsPass2[secretID] = true

			content, err := getSecretContent(secretID)
			if err != nil {
				// Error already logged in debug mode
				continue
			}

			certs := parseCertificates(content)
			if len(certs) == 0 {
				continue
			}

			fmt.Printf("--- Secret Name: %s ---\n", secretName)
			for _, cert := range certs {
				printCertInfo(cert)

				if cert.IsCA {
					fmt.Println("  - Type     : CA Certificate")
				} else {
					fmt.Println("  - Type     : Server/Client Certificate")
					opts := x509.VerifyOptions{Roots: caPool}
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
						fmt.Println("  - DB SAN Check: FAILED")
						overallSuccess = false
					}
				}
			}
		}
	}

	// --- Final Summary ---
	fmt.Println("\n======================================================================")
	fmt.Println("## Overall Status")
	fmt.Println("======================================================================")
	if overallSuccess {
		fmt.Println("All tests passed.")
	} else {
		fmt.Println("One or more tests failed. Please review the report.")
	}
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
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("running podman ps: %w", err)
	}

	output := strings.TrimSpace(out.String())
	debugf("podman ps output:\n%s", output)
	if output == "" {
		return []string{}, nil
	}

	return strings.Split(output, "\n"), nil
}

func getSecretDefinitions(containerName string) ([]string, error) {
	const formatTemplate = `{{range .Config.CreateCommand}}{{.}}{{"\n"}}{{end}}`
	cmd := exec.Command("podman", "inspect", containerName, "--format", formatTemplate)
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("running podman inspect: %w", err)
	}

	fullOutput := out.String()
	debugf("podman inspect for %s output:\n%s", containerName, fullOutput)

	var secretDefs []string
	lines := strings.Split(fullOutput, "\n")
	for i, line := range lines {
		if strings.Contains(line, "--secret") && (i+1) < len(lines) {
			secretLine := lines[i+1]
			debugf("Found potential secret definition line: %s", secretLine)
			if !strings.Contains(secretLine, "type=env") {
				secretDefs = append(secretDefs, secretLine)
			}
		}
	}

	return secretDefs, nil
}

func parseSecretName(secretDef string) string {
	parts := strings.Split(secretDef, ",")
	return parts[0]
}

func getSecretID(secretName string) (string, error) {
	cmd := exec.Command("podman", "secret", "inspect", "--format", "{{.ID}}", secretName)
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("running podman secret inspect for %s: %w", secretName, err)
	}

	return strings.TrimSpace(out.String()), nil
}