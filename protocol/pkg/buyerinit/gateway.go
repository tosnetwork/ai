package buyerinit

import (
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// maxGatewayTokenBytes bounds the bearer token, as the agent reads it.
const maxGatewayTokenBytes = 4096

func cleanAbsolute(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }

// gatewayProblems applies the agent's rules for the optional gateway and
// catalog (MCP_BUYER_ADAPTER_V1 4.3 and 4.4) to the inputs, so init never
// writes a configuration the agent would refuse.
func gatewayProblems(in Input) []string {
	var problems []string
	if in.GatewayURL == "" {
		if in.GatewayCAFile != "" || in.GatewayTokenFile != "" {
			problems = append(problems, "--gateway-ca-file and --gateway-token-file need --gateway-url")
		}
	} else {
		parsed, err := url.Parse(in.GatewayURL)
		switch {
		case err != nil:
			problems = append(problems, "--gateway-url does not parse as a URL")
		case parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
			(parsed.Path != "" && parsed.Path != "/") || parsed.String() != in.GatewayURL:
			problems = append(problems, "--gateway-url must be a bare http(s) base URL")
		case parsed.Scheme == "https":
			if in.GatewayCAFile == "" {
				problems = append(problems, "an https --gateway-url needs --gateway-ca-file")
			}
		case parsed.Scheme == "http":
			host := parsed.Hostname()
			if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
				problems = append(problems, "--gateway-url may use http only on a loopback address")
			}
			if in.GatewayCAFile != "" {
				problems = append(problems, "--gateway-ca-file pins a CA for a plaintext gateway")
			}
		default:
			problems = append(problems, "--gateway-url must be https, or http on a loopback address")
		}
		if !cleanAbsolute(in.GatewayTokenFile) {
			problems = append(problems, "a gateway needs --gateway-token-file, an absolute clean path")
		}
		if in.GatewayCAFile != "" && !cleanAbsolute(in.GatewayCAFile) {
			problems = append(problems, "--gateway-ca-file must be an absolute clean path")
		}
	}
	if in.CatalogDir != "" && !cleanAbsolute(in.CatalogDir) {
		problems = append(problems, "--catalog-dir must be an absolute clean path")
	}
	return problems
}

// checkGatewayFiles reads the gateway token and CA files as the agent will:
// the token file is a custody-owned regular file closed to group and others
// holding one printable token, and the CA file holds a PEM certificate.
func checkGatewayFiles(in Input) error {
	if in.GatewayURL == "" {
		return nil
	}
	raw, err := readPrivateFile(in.GatewayTokenFile, maxGatewayTokenBytes+1)
	if err != nil {
		return errors.New("buyerinit: --gateway-token-file must be a regular file private to the custody account " +
			"(0600) holding the token")
	}
	token := strings.TrimSuffix(string(raw), "\n")
	if token == "" || len(token) > maxGatewayTokenBytes {
		return errors.New("buyerinit: --gateway-token-file holds no token of at most 4096 bytes")
	}
	for index := 0; index < len(token); index++ {
		if token[index] < 0x21 || token[index] > 0x7e {
			return errors.New("buyerinit: the gateway token must be printable ASCII without spaces")
		}
	}
	if in.GatewayCAFile != "" {
		info, err := os.Stat(in.GatewayCAFile)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return errors.New("buyerinit: --gateway-ca-file must be a regular file of at most 1 MiB")
		}
		pem, err := os.ReadFile(in.GatewayCAFile)
		if err != nil || !x509.NewCertPool().AppendCertsFromPEM(pem) {
			return errors.New("buyerinit: --gateway-ca-file holds no PEM certificate")
		}
	}
	return nil
}
