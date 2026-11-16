package carrierapi

import (
	"encoding/json"
	"testing"
)

// A request the decoder accepts re-validates after a JSON round trip.
func FuzzDecodeRequest(f *testing.F) {
	f.Add([]byte(`{"schema":"tos.messaging.carrier-request.v1","op":"carrier.deliver","packet_sender_agent_id":"agent_` +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `","frame_base64":"ZnJhbWU="}`))
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		request, err := DecodeRequest(raw)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeRequest(encoded); err != nil {
			t.Fatalf("an accepted request did not survive a round trip: %v", err)
		}
	})
}

func FuzzDecodeResponse(f *testing.F) {
	f.Add([]byte(`{"schema":"tos.messaging.carrier-response.v1","result":"carried"}`))
	f.Add([]byte(`{"schema":"tos.messaging.carrier-response.v1","result":"carried","relay_ttl_seconds":3600}`))
	f.Add([]byte(`{"schema":"tos.messaging.carrier-response.v1","result":"refused","code":"peer-cap"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, op := range []Op{OpCarry, OpDeliver, OpDeliveryAck} {
			response, err := DecodeResponse(op, raw)
			if err != nil {
				continue
			}
			if err := ValidateResponse(op, response); err != nil {
				t.Fatalf("an accepted response does not validate: %v", err)
			}
		}
	})
}
