package nativecore

import (
	"fmt"
)

// ServiceActorTokenRefusalV1 records a recognized contract refusal. Its path
// flags distinguish transaction exits, funding reasons, and balance results.
type ServiceActorTokenRefusalV1 struct {
	Code                  uint16
	Name                  string
	Throw, Reason, Result bool
}

func (r ServiceActorTokenRefusalV1) Error() string {
	return fmt.Sprintf("token actor refusal %d (%s)", r.Code, r.Name)
}

var tokenRefusalNames = [...]string{
	"not_owner", "inactive", "insufficient_payment", "invalid_response_sla", "invalid_refund_claim_window", "invalid_cleanup_bounty", "insufficient_storage_fee", "capacity_exceeded_global", "capacity_exceeded_caller", "request_id_overflow", "unknown_op", "bad_response_signature", "response_window_closed", "request_not_pending", "expire_too_early", "expire_too_late", "refund_claim_expired", "refund_not_found", "not_refund_caller", "sweep_too_early", "request_not_live", "insufficient_balance", "insufficient_revenue", "not_authorized", "rate_limited", "bad_attestor_key", "terms_mismatch", "amount_range", "operating_reserve_unfunded", "insufficient_execution_payment", "payout_in_flight", "returned_not_found", "asset_route_invalid", "asset_not_recognized", "invalid_destination", "not_accepting_tokens", "surplus_insufficient", "exposure_cap", "abandon_too_early", "malformed_payload", "payout_not_found", "recheck_not_allowed", "recheck_too_early", "balance_query_busy", "attestor_keys_full",
}

// ServiceActorTokenRefusalInfo is shared by transaction and log decoders, so
// adding an admission reason cannot accidentally authorize an unknown reason.
func ServiceActorTokenRefusalInfo(code uint16) (ServiceActorTokenRefusalV1, error) {
	r := ServiceActorTokenRefusalV1{Code: code}
	switch code {
	case 9:
		r.Name = "cell_underflow"
		r.Throw = true
	case 62:
		r.Name = "pq_key_length"
		r.Throw = true
	case 63:
		r.Name = "pq_malformed_key"
		r.Throw = true
	default:
		if code < 1900 || code > 1944 {
			return r, fmt.Errorf("unknown token actor refusal code %d", code)
		}
		r.Name = tokenRefusalNames[code-1900]
		switch code {
		case 1901, 1902, 1903, 1904, 1905, 1906, 1907, 1908, 1909, 1923, 1924, 1925, 1926, 1927, 1928, 1929, 1932, 1933, 1934, 1935, 1937, 1939, 1944:
			r.Reason = true
		}
		switch code {
		case 1901, 1907, 1908, 1923, 1924, 1925, 1926, 1928, 1932, 1933, 1935, 1939:
		default:
			r.Throw = true
		}
		r.Result = code == 1936
	}
	return r, nil
}

// DecodeServiceActorTokenRefusalCode converts a reported failure into a typed
// refusal. Unknown codes remain errors rather than being read as success.
func DecodeServiceActorTokenRefusalCode(code int64) error {
	if code < 0 || code > 65535 {
		return fmt.Errorf("token actor refusal code outside uint16: %d", code)
	}
	info, err := ServiceActorTokenRefusalInfo(uint16(code))
	if err != nil {
		return err
	}
	return info
}
