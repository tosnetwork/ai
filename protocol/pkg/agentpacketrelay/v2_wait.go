package agentpacketrelay

import (
	"context"
	"errors"
)

var errWaitBusy = errors.New("mailbox already has a waiting request")
var errWaitFull = errors.New("relay waiting request table full")

func (s *V2Store) notifyLocked(agent string) {
	digest, ok := parseAgentText(agent)
	if !ok {
		return
	}
	if ch := s.waiters[digest]; ch != nil {
		select {
		case <-ch:
		default:
			close(ch)
		}
	}
}
func (s *V2Store) waitSnapshot(ctx context.Context, agent agentDigest, now uint64, previous chan struct{}) ([]V2MailboxEntry, chan struct{}, error) {
	if err := s.mu.lock(ctx); err != nil {
		return nil, nil, err
	}
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return nil, nil, err
	}
	if previous == nil && s.waiters[agent] != nil {
		return nil, nil, errWaitBusy
	}
	if previous != nil && s.waiters[agent] != previous {
		return nil, nil, ErrStoreUnavailable
	}
	entries := s.listLocked(agent, now)
	if len(entries) > 0 {
		return entries, previous, nil
	}
	if previous == nil && len(s.waiters) >= s.controlLimits.Waiters {
		return nil, nil, errWaitFull
	}
	if previous == nil {
		previous = make(chan struct{})
		s.waiters[agent] = previous
	} else {
		select {
		case <-previous:
			previous = make(chan struct{})
			s.waiters[agent] = previous
		default:
		}
	}
	return entries, previous, nil
}
func (s *V2Store) endWait(agent agentDigest, ch chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.waiters[agent] == ch {
		delete(s.waiters, agent)
	}
}
