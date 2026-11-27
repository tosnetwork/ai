package agenttransport

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type credentialCorpus struct {
	Schema      string `json:"schema"`
	Credentials []struct {
		Name         string   `json:"name"`
		Chain        []string `json:"chain"`
		CredentialID string   `json:"credential_id"`
		Holder       string   `json:"holder"`
		Length       int      `json:"length"`
		Wire         string   `json:"wire"`
	} `json:"credentials"`
	Evaluations []struct {
		Name       string `json:"name"`
		Credential string `json:"credential"`
		Now        uint64 `json:"now"`
		RelayURL   string `json:"relay_url"`
		Operation  string `json:"operation"`
		Usage      *struct {
			StoredEnvelopes uint64 `json:"stored_envelopes"`
			StoredBytes     uint64 `json:"stored_bytes"`
			EnvelopeBytes   uint64 `json:"envelope_bytes"`
		} `json:"usage"`
		Expect string `json:"expect"`
	} `json:"evaluations"`
	Proofs []struct {
		Name             string `json:"name"`
		Agent            string `json:"agent"`
		Operation        string `json:"operation"`
		RelayURL         string `json:"relay_url"`
		Method           string `json:"method"`
		Path             string `json:"path"`
		Body             string `json:"body"`
		Now              uint64 `json:"now"`
		Preimage         string `json:"preimage"`
		CredentialHeader string `json:"credential_header"`
		ProofHeader      string `json:"proof_header"`
		Expect           string `json:"expect"`
	} `json:"proofs"`
	Negative []struct {
		Name  string `json:"name"`
		Stage string `json:"stage"`
		Class string `json:"class"`
		Wire  string `json:"wire"`
	} `json:"negative_credentials"`
}

var vectorOperations = map[string]Operation{"deposit": OperationDeposit, "list": OperationList, "fetch": OperationFetch, "publish": OperationPublish, "revoke": OperationRevoke}

func classOf(err error) string {
	switch {
	case err == nil:
		return "accept"
	case errors.Is(err, ErrCredentialInvalid) && errors.Is(err, ErrCredentialScope):
		return "two classes"
	case errors.Is(err, ErrCredentialInvalid):
		return "credential_invalid"
	case errors.Is(err, ErrCredentialScope):
		return "credential_scope"
	default:
		return "unclassified: " + err.Error()
	}
}

// TestFrozenCredentialVectors only reads the frozen corpus; a mismatch is a
// finding, never a reason to regenerate it.
func TestFrozenCredentialVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../spec/test-vectors/agent-transport-credential-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus credentialCorpus
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != "tos.agent-transport-credential-v1.vectors" || len(corpus.Credentials) != 9 || len(corpus.Evaluations) != 33 || len(corpus.Proofs) != 24 || len(corpus.Negative) != 47 {
		t.Fatal("incomplete credential corpus")
	}
	credentials := map[string]*Credential{}
	for _, v := range corpus.Credentials {
		t.Run("credential/"+v.Name, func(t *testing.T) {
			wire, err := hex.DecodeString(v.Wire)
			if err != nil || len(wire) != v.Length {
				t.Fatal("wire")
			}
			c := decode(t, wire)
			encoded, err := c.Encode()
			if err != nil || hex.EncodeToString(encoded) != v.Wire {
				t.Fatalf("re-encoding: %v", err)
			}
			for i, value := range c.ChainValues() {
				if hex.EncodeToString(value[:]) != v.Chain[i] {
					t.Fatalf("chain_%d", i)
				}
			}
			id, holder := c.CredentialID(), c.HolderKey()
			if hex.EncodeToString(id[:]) != v.CredentialID || hex.EncodeToString(holder[:]) != v.Holder {
				t.Fatal("credential id or holder")
			}
			credentials[v.Name] = c
		})
	}
	for _, v := range corpus.Evaluations {
		t.Run("evaluation/"+v.Name, func(t *testing.T) {
			c := credentials[v.Credential]
			err := c.CheckScope(v.Now, v.RelayURL, vectorOperations[v.Operation])
			if err == nil && v.Usage != nil {
				err = c.CheckDeposit(LaneUsage{StoredEnvelopes: v.Usage.StoredEnvelopes, StoredBytes: v.Usage.StoredBytes, EnvelopeBytes: v.Usage.EnvelopeBytes})
			}
			if got := classOf(err); got != v.Expect {
				t.Fatalf("got %s, want %s", got, v.Expect)
			}
		})
	}
	for _, v := range corpus.Proofs {
		t.Run("proof/"+v.Name, func(t *testing.T) {
			body, err := hex.DecodeString(v.Body)
			if err != nil {
				t.Fatal(err)
			}
			request := ProofRequest{RelayURL: v.RelayURL, Method: v.Method, Path: v.Path, Body: body}
			checked, err := CheckRequest(Request{AgentID: v.Agent, Operation: vectorOperations[v.Operation], Proof: request, CredentialValue: v.CredentialHeader, ProofValue: v.ProofHeader, Now: v.Now})
			if got := classOf(err); got != v.Expect {
				t.Fatalf("got %s (%v), want %s", got, err, v.Expect)
			}
			if err == nil {
				preimage, err := ProofPreimage(checked.Credential.CredentialID(), request, checked.Proof.IssuedAt, checked.Proof.Nonce)
				if err != nil || hex.EncodeToString(preimage) != v.Preimage {
					t.Fatalf("preimage: %v", err)
				}
			}
		})
	}
	for _, v := range corpus.Negative {
		t.Run(v.Stage+"/"+v.Name, func(t *testing.T) {
			wire, err := hex.DecodeString(v.Wire)
			if err != nil {
				t.Fatal(err)
			}
			c, err := DecodeCredential(wire)
			if v.Stage == "chain" {
				if err != nil {
					t.Fatalf("chain negative must decode: %v", err)
				}
				err = c.VerifyChain()
			}
			if got := classOf(err); got != v.Class {
				t.Fatalf("got %s, want %s", got, v.Class)
			}
		})
	}
}
