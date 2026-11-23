package servicebridge

import "errors"

// Library entry points of the provider agent (spec/docs/MCP_PROVIDER_ADAPTER_V1.md):
// the agent holds the node's serve lock before its offer exists, redacts the
// node's endpoints in what it reports, and shows the validity window of the
// key card an offer file carries.

// LockServe takes the state directory's serve lock without waiting, as
// OpenNode does, and returns its release. The provider agent holds it while
// the node has no provider section yet, so `serve` and a second agent are
// refused from its start, and releases it just before it opens the node.
// It returns ErrNodeServing when another process serves the node.
func LockServe(stateDir string) (func(), error) {
	return lockServe(stateDir)
}

// RedactEndpoints replaces every spelling of a configured endpoint URL in
// message with its position, as the node's own reports do.
func RedactEndpoints(message string, endpoints []string) string {
	return redactEndpoints(message, endpoints)
}

// OfferKeyCardWindow decodes the key card packet an offer file carries for
// agentID, without the finalized check, and returns its validity window.
func OfferKeyCardWindow(raw []byte, agentID string) (notBeforeUnix, notAfterUnix uint64, err error) {
	if len(raw) == 0 {
		return 0, 0, errors.New("servicebridge: the offer carries no key card")
	}
	card, err := decodePeerCard(raw, agentID, "")
	if err != nil {
		return 0, 0, err
	}
	return card.Card.NotBeforeUnix, card.Card.NotAfterUnix, nil
}
