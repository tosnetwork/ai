package agentpacketrelay

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

type v2Mark struct {
	Version string `json:"version"`
	Mark    uint64 `json:"high_water_mark"`
}

// V2Replay persists only the high-water mark, not a write per request. The
// pending candidate is monotonic even after an uncertain rename/directory sync.
type V2Replay struct {
	mu        sync.Mutex
	table     *agenttransport.ReplayTable
	disk      *v2Disk
	candidate uint64
	closed    bool
}

func openV2Replay(d *v2Disk, fresh bool, config agenttransport.ReplayConfig, now uint64, recoverFloor *uint64, audit func(uint64)) (*V2Replay, error) {
	var mark v2Mark
	raw, readErr := readV2File(d.root+"/REPLAY", 1024)
	if readErr == nil {
		readErr = decodeV2(raw, &mark)
		if readErr == nil && (mark.Version != "tos.service.relay-replay.v2" || mark.Mark == 0) {
			readErr = errors.New("invalid replay mark")
		}
	}
	var table *agenttransport.ReplayTable
	var err error
	if fresh {
		if recoverFloor != nil {
			return nil, errors.New("replay recovery is not fresh initialization")
		}
		table, err = agenttransport.NewReplayTable(config)
	} else {
		if recoverFloor == nil && readErr != nil {
			return nil, errors.New("used V2 store has a missing or corrupt replay record")
		}
		if recoverFloor != nil {
			if audit == nil || now > ^uint64(0)-agenttransport.MarkLeadSeconds || *recoverFloor < now+agenttransport.MarkLeadSeconds || (readErr == nil && *recoverFloor < mark.Mark) {
				return nil, errors.New("explicit replay recovery needs an audited floor at least now+140 and every valid old mark")
			}
			mark = v2Mark{"tos.service.relay-replay.v2", *recoverFloor}
			raw, err = encodeV2(mark)
			if err != nil {
				return nil, err
			}
			if err = d.write("REPLAY", raw); err != nil {
				return nil, err
			}
			audit(*recoverFloor)
		}
		table, err = agenttransport.RestoreReplayTable(config, mark.Mark)
	}
	if err != nil {
		return nil, err
	}
	replay := &V2Replay{table: table, disk: d, candidate: mark.Mark}
	if err = replay.Record(now); err != nil {
		return nil, err
	}
	return replay, nil
}

// Record publishes a bound to admission only after file and directory sync.
func (r *V2Replay) Record(now uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrStoreUnavailable
	}
	r.candidate = max(r.candidate, r.table.NextMark(now))
	raw, err := encodeV2(v2Mark{"tos.service.relay-replay.v2", r.candidate})
	if err != nil {
		return err
	}
	if err = r.disk.write("REPLAY", raw); err != nil {
		return err
	}
	return r.table.MarkRecorded(r.candidate)
}

// checkedReplayIdentity never reads identity from an unchecked credential or
// caller-supplied ReplayIdentity, even if someone forged the public wrapper.
func checkedReplayIdentity(checked agenttransport.CheckedRequest) (agenttransport.ReplayIdentity, error) {
	if checked.Credential == nil {
		return agenttransport.ReplayIdentity{}, agenttransport.ErrCredentialInvalid
	}
	if err := checked.Credential.VerifyChain(); err != nil {
		return agenttransport.ReplayIdentity{}, err
	}
	return checked.ReplayIdentity()
}
func (r *V2Replay) Claim(checked agenttransport.CheckedRequest, now uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrStoreUnavailable
	}
	identity, err := checkedReplayIdentity(checked)
	if err != nil {
		return err
	}
	return r.table.Claim(identity, checked.Proof, now)
}
func (r *V2Replay) RetryAfter(issuedAt uint64) uint64 { return r.table.RetryAfter(issuedAt) }
func (r *V2Replay) State() (uint64, uint64, int)      { return r.table.State() }
func (r *V2Replay) Run(ctx context.Context, now func() time.Time, onFailure func()) {
	ticker := time.NewTicker(agenttransport.MarkIntervalSeconds * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.Record(unixNow(now())); err != nil && onFailure != nil {
				onFailure()
			}
		}
	}
}

func (r *V2Replay) close() { r.mu.Lock(); defer r.mu.Unlock(); r.closed = true }
