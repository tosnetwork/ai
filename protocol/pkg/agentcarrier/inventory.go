package agentcarrier

import (
	"context"
	"encoding/hex"
	"sort"
	"strings"
)

// The inventory makes a missing used file distinguishable from a new lane.
// New files precede inventory admission; removals follow inventory retirement.
// A crash can therefore leave an unreferenced file, never a referenced hole.
type inventory struct {
	Identity   identity `json:"identity"`
	Keys       []string `json:"keys"`
	Deliveries []string `json:"deliveries"`
}

func validNames(names []string, prefix string, limit int) bool {
	if len(names) > limit {
		return false
	}
	for i, name := range names {
		if len(name) != len(prefix)+64 || !strings.HasPrefix(name, prefix) || (i > 0 && names[i-1] >= name) {
			return false
		}
		if _, err := hex.DecodeString(name[len(prefix):]); err != nil || strings.ToLower(name) != name {
			return false
		}
	}
	return true
}
func (l *Lane) inventory() (inventory, error) {
	var index inventory
	if l.disk.read("identity", &index) != nil || index.Identity != l.identity() || index.Keys == nil || index.Deliveries == nil || !validNames(index.Keys, "key-", MaxKeys) || !validNames(index.Deliveries, "out-", l.config.OutboxLimit) {
		return index, ErrStorage
	}
	return index, nil
}
func (l *Lane) indexed(name string) (bool, error) {
	if err := l.meta.lock(context.Background()); err != nil {
		return false, err
	}
	defer l.meta.unlock()
	index, err := l.inventory()
	if err != nil {
		return false, err
	}
	names := index.Deliveries
	if strings.HasPrefix(name, "key-") {
		names = index.Keys
	}
	at := sort.SearchStrings(names, name)
	return at < len(names) && names[at] == name, nil
}
func (l *Lane) index(ctx context.Context, name string, add bool) error {
	if err := l.meta.lock(ctx); err != nil {
		return err
	}
	defer l.meta.unlock()
	index, err := l.inventory()
	if err != nil {
		return err
	}
	names := &index.Deliveries
	limit := l.config.OutboxLimit
	if strings.HasPrefix(name, "key-") {
		names = &index.Keys
		limit = MaxKeys
	}
	at := sort.SearchStrings(*names, name)
	exists := at < len(*names) && (*names)[at] == name
	if add && !exists {
		if len(*names) >= limit {
			return ErrCapacity
		}
		*names = append(*names, name)
		sort.Strings(*names)
	} else if !add && exists {
		*names = append((*names)[:at], (*names)[at+1:]...)
	} else {
		return ErrStorage
	}
	return l.disk.write("identity", index)
}
