package provideragent

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"sort"
	"strings"

	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

// untrustedKeys are the free-text fields that can quote a buyer, a relay,
// tosctl or the executor. In a client view each is renamed untrusted_<key>
// (section 4.3 and section 9).
var untrustedKeys = map[string]bool{
	"detail": true, "reason": true, "error": true, "message": true, "withdrawals_error": true,
	"relay_error": true, "state_reason": true, "line": true,
}

// droppedKeys are the large or buyer-supplied fields a client view replaces
// with their SHA-256 and length.
var droppedKeys = map[string]bool{"package_base64": true, "receipt_boc_base64": true}

// redactor turns a custody view into the client's view.
type redactor struct {
	// paths are custody paths with their configuration keys, longest first.
	paths []replacement
	// endpoints are the configured RPC endpoints.
	endpoints []string
	// secrets are values never shown, such as the vault URL.
	secrets []replacement
	// relays are relay URLs that may not be shown as they are.
	relays []replacement
}

type replacement struct{ text, name string }

// newRedactor collects the custody paths of the rail configuration and the
// agent configuration, the endpoints and the vault URL.
func newRedactor(rail servicebridge.NodeConfig, config Config, railPath, vaultURL string) *redactor {
	r := &redactor{endpoints: append([]string(nil), rail.RPCEndpoints...)}
	add := func(name, path string) {
		if path != "" && path != "/" {
			r.paths = append(r.paths, replacement{text: path, name: "<" + name + ">"})
		}
	}
	add("rail_config", railPath)
	add("state_dir", rail.StateDir)
	add("receiver_socket", rail.ReceiverSocket)
	add("registry_code_boc_file", rail.RegistryCodeBOC)
	add("chain_global_config_file", rail.GlobalConfigFile)
	add("relay_ca_file", rail.RelayCAFile)
	add("tosctl.binary", rail.TOSCTL.Binary)
	add("tosctl.config_path", rail.TOSCTL.ConfigPath)
	for agent, socket := range rail.DirectPeers {
		add("direct_peers["+agent+"]", socket)
	}
	if provider := rail.Provider; provider != nil {
		add("provider.manifest_file", provider.ManifestFile)
		add("provider.executor_socket", provider.ExecutorSocket)
		add("provider.executor_binary", provider.ExecutorBinary)
		add("provider.containerd_socket", provider.ContainerdSocket)
		add("provider.fifo_dir", provider.FIFODir)
		add("provider.offer_file", provider.OfferFile)
		add("provider.gateway_key_card_file", provider.GatewayCardFile)
	}
	if rail.Token != nil {
		add("token.monitor_report", rail.Token.MonitorReport)
		for _, actor := range rail.Token.Actors {
			add("token.manifest_file", actor.ManifestFile)
		}
	}
	add("agent.state_dir", config.StateDir)
	add("agent.socket_dir", config.SocketDir)
	add("offer.executor_socket", config.Offer.ExecutorSocket)
	add("offer.executor_binary", config.Offer.ExecutorBinary)
	add("offer.containerd_socket", config.Offer.ContainerdSocket)
	add("offer.fifo_dir", config.Offer.FIFODir)
	add("offer.offer_path", config.Offer.OfferPath)
	add("offer.gateway_card_path", config.Offer.GatewayCardPath)
	sort.SliceStable(r.paths, func(i, j int) bool { return len(r.paths[i].text) > len(r.paths[j].text) })
	if vaultURL != "" {
		r.secrets = append(r.secrets, replacement{text: vaultURL, name: "<vault_url>"})
	}
	for index, relay := range rail.RelayURLs {
		parsed, err := url.Parse(relay)
		if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
			strings.ContainsAny(relay, "?#@") {
			r.relays = append(r.relays, replacement{text: relay, name: fmt.Sprintf("relay_urls[%d]", index)})
		}
	}
	sort.SliceStable(r.relays, func(i, j int) bool { return len(r.relays[i].text) > len(r.relays[j].text) })
	return r
}

// text redacts one string: secrets first, then relay URLs that carry user
// information, a query or a fragment, then every spelling of the RPC
// endpoints, then custody paths, longest first.
func (r *redactor) text(value string) string {
	for _, secret := range r.secrets {
		value = strings.ReplaceAll(value, secret.text, secret.name)
	}
	for _, relay := range r.relays {
		value = strings.ReplaceAll(value, relay.text, relay.name)
	}
	value = servicebridge.RedactEndpoints(value, r.endpoints)
	for _, path := range r.paths {
		value = strings.ReplaceAll(value, path.text, path.name)
	}
	return value
}

// view renders value as the client sees it: every string redacted, the
// untrusted free-text fields renamed, and the large fields replaced by their
// digest and length.
func (r *redactor) view(value any) (json.RawMessage, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(r.walk(generic))
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func (r *redactor) walk(value any) any {
	switch typed := value.(type) {
	case string:
		return r.text(typed)
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			out[index] = r.walk(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			if droppedKeys[key] {
				text, _ := item.(string)
				body, err := base64.StdEncoding.DecodeString(text)
				if err != nil {
					body = []byte(text)
				}
				sum := sha256.Sum256(body)
				out[key+"_sha256"] = hex.EncodeToString(sum[:])
				out[key+"_bytes"] = len(body)
				continue
			}
			name := key
			if untrustedKeys[key] {
				name = "untrusted_" + key
			}
			out[name] = r.walk(item)
		}
		return out
	}
	return value
}

// bigText renders a contract amount; a missing one is "0".
func bigText(value *big.Int) string {
	if value == nil {
		return "0"
	}
	return value.String()
}
