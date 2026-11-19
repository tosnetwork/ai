package payload

// RetiredKinds are event kinds that once had a meaning and are reserved
// forever. None may be given a codec or an event class again, under any
// payload schema: a peer still holding the old meaning would read a new body
// as the old one.
//
// Commerce is outside Messenger's scope. Agents negotiate through Intent
// Exchange Agreements and settle on the Service Actor rail; Messenger carries
// those objects only as non-authorizing application payloads. The kinds below
// carried an escrow-era negotiation and its chain references, and nothing
// replaces them inside Messenger.
var RetiredKinds = []string{
	"negotiation.proposal",
	"negotiation.counterproposal",
	"negotiation.withdraw",
	"negotiation.intent.accept",
	"negotiation.intent.reject",
	"service.quote.reference",
	"service.escrow.reference",
	"service.receipt.reference",
}

// RetiredSchemas are payload schema identifiers reserved for the same reason.
// No codec may emit or accept any of them, under any kind.
var RetiredSchemas = []string{
	"tos.messaging.payload.negotiation-proposal.v1",
	"tos.messaging.payload.negotiation-proposal.v2",
	"tos.messaging.payload.negotiation-proposal.v3",
	"tos.messaging.payload.negotiation-counterproposal.v1",
	"tos.messaging.payload.negotiation-counterproposal.v2",
	"tos.messaging.payload.negotiation-counterproposal.v3",
	"tos.messaging.payload.negotiation-withdraw.v1",
	"tos.messaging.payload.negotiation-intent-accept.v1",
	"tos.messaging.payload.negotiation-intent-accept.v2",
	"tos.messaging.payload.negotiation-intent-accept.v3",
	"tos.messaging.payload.negotiation-intent-reject.v1",
	"tos.messaging.payload.quote-reference.v1",
	"tos.messaging.payload.escrow-reference.v1",
	"tos.messaging.payload.receipt-reference.v1",
}

// RetiredKind reports whether an event kind is reserved.
func RetiredKind(kind string) bool {
	for _, retired := range RetiredKinds {
		if kind == retired {
			return true
		}
	}
	return false
}

// RetiredSchema reports whether a payload schema is reserved.
func RetiredSchema(schema string) bool {
	for _, retired := range RetiredSchemas {
		if schema == retired {
			return true
		}
	}
	return false
}
