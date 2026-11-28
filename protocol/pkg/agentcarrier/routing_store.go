package agentcarrier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"sort"
	"strings"
)

const MaxRoutingRecords = 4096

// Each private namespace has its own single-writer lock and durable inventory.
// Indexed holes refuse; unindexed files can only be interrupted admissions.
type routingIndex struct {
	Identity identity `json:"identity"`
	Names    []string `json:"names"`
}
type routingStore struct {
	disk     *disk
	identity identity
	gate     gate
}

func openRoutingStore(path string, id identity) (*routingStore, error) {
	d, err := openDisk(path)
	if err != nil {
		return nil, err
	}
	s := &routingStore{d, id, make(gate, 1)}
	names, err := d.names(MaxRoutingRecords + 3)
	if err != nil {
		return nil, errors.Join(err, d.close())
	}
	for _, name := range names {
		if strings.HasPrefix(name, "write-") {
			if len(name) != 38 {
				return nil, errors.Join(ErrStorage, d.close())
			}
			if _, err = hex.DecodeString(name[6:]); err != nil {
				return nil, errors.Join(ErrStorage, d.close())
			}
			info, e := d.root.Lstat(name)
			if e != nil || !singlePrivate(info) {
				return nil, errors.Join(ErrStorage, d.close())
			}
			if err = d.remove(name); err != nil {
				return nil, errors.Join(err, d.close())
			}
		}
	}
	var index routingIndex
	err = d.read("identity", &index)
	if errors.Is(err, os.ErrNotExist) {
		names, e := d.names(MaxRoutingRecords + 3)
		if e != nil || len(names) != 1 || names[0] != "lock" {
			return nil, errors.Join(ErrStorage, d.close())
		}
		err = d.write("identity", routingIndex{id, []string{}})
	}
	if err == nil {
		_, err = s.index()
	}
	if err == nil {
		index, readErr := s.index()
		err = readErr
		if err == nil {
			names, e := d.names(MaxRoutingRecords + 3)
			err = e
			expected := map[string]bool{}
			for _, n := range index.Names {
				expected[n] = true
			}
			for _, n := range names {
				if n == "identity" || n == "lock" {
					continue
				}
				if !validRoutingName(n) {
					err = ErrStorage
					break
				}
				var record map[string]any
				if e = d.read(n, &record); e != nil {
					err = ErrStorage
					break
				}
				if expected[n] {
					delete(expected, n)
				} else if e = d.remove(n); e != nil {
					err = e
					break
				}
			}
			if len(expected) != 0 {
				err = ErrStorage
			}
		}
	}
	if err != nil {
		if closeErr := d.close(); closeErr != nil {
			return nil, ErrStorage
		}
		return nil, err
	}
	return s, nil
}
func validRoutingName(n string) bool {
	if len(n) != 66 || !strings.HasPrefix(n, "r-") {
		return false
	}
	b, e := hex.DecodeString(n[2:])
	return e == nil && len(b) == 32 && strings.ToLower(n) == n
}
func routingName(id string) string {
	h := sha256.Sum256([]byte(id))
	return "r-" + hex.EncodeToString(h[:])
}
func (s *routingStore) index() (routingIndex, error) {
	var i routingIndex
	if s.disk.read("identity", &i) != nil || i.Identity != s.identity || i.Names == nil || len(i.Names) > MaxRoutingRecords {
		return i, ErrStorage
	}
	for p, n := range i.Names {
		if !validRoutingName(n) || (p > 0 && i.Names[p-1] >= n) {
			return i, ErrStorage
		}
	}
	return i, nil
}
func (s *routingStore) read(name string, value any) error {
	i, e := s.index()
	if e != nil {
		return e
	}
	at := sort.SearchStrings(i.Names, name)
	if at == len(i.Names) || i.Names[at] != name {
		return os.ErrNotExist
	}
	if e = s.disk.read(name, value); e != nil {
		return ErrStorage
	}
	return nil
}
func (s *routingStore) write(name string, value any) error {
	i, e := s.index()
	if e != nil || !validRoutingName(name) {
		return ErrStorage
	}
	at := sort.SearchStrings(i.Names, name)
	exists := at < len(i.Names) && i.Names[at] == name
	if !exists && len(i.Names) >= MaxRoutingRecords {
		return ErrCapacity
	}
	if e = s.disk.write(name, value); e != nil {
		return e
	}
	if exists {
		return nil
	}
	i.Names = append(i.Names, name)
	sort.Strings(i.Names)
	return s.disk.write("identity", i)
}
func (s *routingStore) remove(name string) error {
	i, e := s.index()
	if e != nil {
		return e
	}
	at := sort.SearchStrings(i.Names, name)
	if at == len(i.Names) || i.Names[at] != name {
		return nil
	}
	i.Names = append(i.Names[:at], i.Names[at+1:]...)
	if e = s.disk.write("identity", i); e != nil {
		return e
	}
	return s.disk.remove(name)
}
func (s *routingStore) lock(ctx context.Context) error { return s.gate.lock(ctx) }
func (s *routingStore) unlock()                        { s.gate.unlock() }
func (s *routingStore) Close() error                   { return s.disk.close() }
