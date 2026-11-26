package servicebridge

import (
	"context"
	"time"
)

// TokenPreflight keeps derived per-actor floor holds separate from the explicit
// operator/model marker. Recovering a floor can never remove that marker.
func TokenPreflight(ctx context.Context, c NodeConfig, env TokenEnv) *PreflightReport {
	env.fill()
	r := &PreflightReport{Schema: PreflightSchema, Version: PreflightVersion, GeneratedUnix: time.Now().Unix(), OK: true}
	add := func(id string, err error) {
		check := PreflightCheck{ID: id, Status: CheckPass, Message: "verified at a finalized checkpoint"}
		if err != nil {
			check.Status = CheckFail
			check.Message = "token provider not ready"
			r.OK = false
		}
		r.Checks = append(r.Checks, check)
	}
	if c.Token == nil {
		return r
	}
	if err := c.Token.Validate(); err != nil {
		add("token.config", err)
		return r
	}
	for _, a := range c.Token.Actors {
		s, err := env.Begin(ctx, c, a)
		if err == nil {
			_, err = tokenOfferAtSession(ctx, c, a, s, true)
		}
		add("token.offer."+a.AssetID, err)
	}
	pause, err := ReadAdmissionPause(c.StateDir)
	if err != nil || pause != nil {
		r.AdmissionPaused = true
		r.OK = false
		r.Checks = append(r.Checks, PreflightCheck{ID: "admission.pause", Status: CheckFail, Message: "local admission is paused"})
	} else {
		r.Checks = append(r.Checks, PreflightCheck{ID: "admission.pause", Status: CheckPass, Message: "local admission open"})
	}
	return r
}
