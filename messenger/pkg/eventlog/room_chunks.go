package eventlog

// Content-addressed records that the fused room record and the room outbox
// name by digest. A large value never lives in a record that a later field
// could push past its bound: the MLS state, the authority delegation, earlier
// memberships and room objects are written here first, and the record that
// names them is the single commit point. A record nothing names is garbage
// (room_gc.go).
//
// Every read recomputes the digest of what it read and refuses a mismatch, so
// a damaged or substituted chunk fails closed instead of being handed to the
// MLS library or published.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/room"
)

const (
	roomStateDir       = "room-mls-state"
	roomBlobDir        = "room-blobs"
	roomObjectChunkDir = "room-object-chunks"

	roomStateChunkSchema  = "tos.messaging.room-mls-state-chunk.v1"
	roomDelegationSchema  = "tos.messaging.room-delegation.v1"
	roomMembershipSchema  = "tos.messaging.room-membership.v1"
	roomObjectChunkSchema = "tos.messaging.room-object-chunk.v1"

	// MLSStateChunkBytes is one staged MLS state chunk. The state bound of
	// MaxMLSStateBytes therefore takes at most MaxMLSStateChunks chunks, each
	// 349,528 bytes in base64, well inside MaxRecordBytes.
	MLSStateChunkBytes = 262144
	MaxMLSStateChunks  = (MaxMLSStateBytes + MLSStateChunkBytes - 1) / MLSStateChunkBytes
	// MaxRoomDelegationBytes bounds the staged authority delegation, as the
	// delegation file bound does.
	MaxRoomDelegationBytes = 64 << 10
	// RoomObjectChunkBytes is one chunk of a room object in the room outbox.
	RoomObjectChunkBytes = 262144
	// MaxRoomObjectBytes is the largest room object: 90 fixed bytes, an
	// 8,192-byte header and a 1 MiB body.
	MaxRoomObjectBytes  = 1056858
	MaxRoomObjectChunks = (MaxRoomObjectBytes + RoomObjectChunkBytes - 1) / RoomObjectChunkBytes

	delegationBlobPrefix = "d-"
	membershipBlobPrefix = "m-"
)

// ErrRoomChunkDigest reports a staged record whose bytes do not reproduce the
// digest it is named by.
var ErrRoomChunkDigest = errors.New("room record does not match its digest")

type roomChunkRecord struct {
	Schema     string `json:"schema"`
	Digest     string `json:"digest"`
	DataBase64 string `json:"data_base64"`
}

type roomMembershipRecord struct {
	Schema  string   `json:"schema"`
	RoomID  string   `json:"room_id"`
	Epoch   uint64   `json:"epoch"`
	Members []string `json:"members"`
	Digest  string   `json:"digest"`
}

// digestHex returns the hex part of a well-formed canonical digest.
func digestHex(digest string) (string, error) {
	if !canon.ValidDigest(digest) {
		return "", errors.New("invalid digest")
	}
	return digest[len("sha256:"):], nil
}

// RoomObjectDigest is the relay object digest of a room object,
// SHA-256(D("tos.messaging.relay-object.v1") || object), as lowercase hex.
// The outbox is keyed by it because it is the digest every part of the object
// carries and every room ack names.
func RoomObjectDigest(object []byte) string {
	hash := sha256.New()
	hash.Write([]byte(canon.DomainRelayObject))
	hash.Write(object)
	return hex.EncodeToString(hash.Sum(nil))
}

// SplitMLSState cuts an opaque MLS state into its staged chunks.
func SplitMLSState(state []byte) ([][]byte, error) {
	if len(state) == 0 || len(state) > MaxMLSStateBytes || canon.IsZero(state) {
		return nil, errors.New("invalid opaque MLS state")
	}
	return splitChunks(state, MLSStateChunkBytes), nil
}

func splitChunks(value []byte, size int) [][]byte {
	chunks := make([][]byte, 0, (len(value)+size-1)/size)
	for start := 0; start < len(value); start += size {
		end := start + size
		if end > len(value) {
			end = len(value)
		}
		chunks = append(chunks, value[start:end])
	}
	return chunks
}

func (j *Journal) roomStatePath(roomID, chunkDigest string) (string, error) {
	if !ids.Room.MatchString(roomID) {
		return "", errors.New("invalid room identifier")
	}
	digest, err := digestHex(chunkDigest)
	if err != nil {
		return "", err
	}
	return filepath.Join(j.root, roomStateDir, roomID[len("room_"):]+"-"+digest+".json"), nil
}

func (j *Journal) roomBlobPath(prefix, digest string) (string, error) {
	value, err := digestHex(digest)
	if err != nil {
		return "", err
	}
	return filepath.Join(j.root, roomBlobDir, prefix+value+".json"), nil
}

func (j *Journal) roomObjectChunkPath(chunkDigest string) (string, error) {
	digest, err := digestHex(chunkDigest)
	if err != nil {
		return "", err
	}
	return filepath.Join(j.root, roomObjectChunkDir, digest+".json"), nil
}

// writeChunk stores data under its digest. A chunk is immutable: if the file
// already exists it must hold exactly these bytes, which a rewrite by an
// interrupted earlier attempt does.
func (j *Journal) writeChunk(path, schema string, data []byte) (string, error) {
	digest := canon.Digest(data)
	if existing, err := readChunk(path, schema, digest); err == nil {
		if string(existing) != string(data) {
			return "", ErrRoomChunkDigest
		}
		return digest, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	encoded, err := json.Marshal(roomChunkRecord{Schema: schema, Digest: digest, DataBase64: base64.StdEncoding.EncodeToString(data)})
	if err != nil {
		return "", err
	}
	if err := j.replace(path, encoded); err != nil {
		return "", err
	}
	return digest, nil
}

func readChunk(path, schema, digest string) ([]byte, error) {
	raw, err := readRecordBytes(path)
	if err != nil {
		return nil, err
	}
	var record roomChunkRecord
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.Schema != schema || record.Digest != digest {
		return nil, errors.New("invalid staged room record")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(record.DataBase64)
	if err != nil || len(data) == 0 {
		return nil, errors.New("invalid staged room record")
	}
	if canon.Digest(data) != digest {
		return nil, ErrRoomChunkDigest
	}
	return data, nil
}

// stageMLSState writes the chunks of one MLS state for a room and returns
// their digests in order.
func (j *Journal) stageMLSState(roomID string, state []byte) ([]string, error) {
	chunks, err := SplitMLSState(state)
	if err != nil {
		return nil, err
	}
	digests := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		path, err := j.roomStatePath(roomID, canon.Digest(chunk))
		if err != nil {
			return nil, err
		}
		digest, err := j.writeChunk(path, roomStateChunkSchema, chunk)
		if err != nil {
			return nil, err
		}
		digests = append(digests, digest)
	}
	return digests, nil
}

// loadMLSState reassembles a staged state, verifying every chunk digest and
// then the state digest.
func (j *Journal) loadMLSState(roomID, stateDigest string, chunkDigests []string) ([]byte, error) {
	if len(chunkDigests) == 0 || len(chunkDigests) > MaxMLSStateChunks || !canon.ValidDigest(stateDigest) {
		return nil, errors.New("invalid MLS state reference")
	}
	state := make([]byte, 0, len(chunkDigests)*MLSStateChunkBytes)
	for index, digest := range chunkDigests {
		path, err := j.roomStatePath(roomID, digest)
		if err != nil {
			return nil, err
		}
		chunk, err := readChunk(path, roomStateChunkSchema, digest)
		if err != nil {
			return nil, err
		}
		// Every chunk but the last is full, so a state has exactly one cut.
		if len(chunk) > MLSStateChunkBytes || (index+1 < len(chunkDigests) && len(chunk) != MLSStateChunkBytes) {
			return nil, errors.New("invalid MLS state chunk length")
		}
		state = append(state, chunk...)
	}
	if len(state) > MaxMLSStateBytes || canon.Digest(state) != stateDigest {
		return nil, ErrRoomChunkDigest
	}
	return state, nil
}

func (j *Journal) stageDelegation(delegationJSON []byte) (string, error) {
	if len(delegationJSON) == 0 || len(delegationJSON) > MaxRoomDelegationBytes {
		return "", errors.New("invalid room authority delegation")
	}
	if _, err := decodeRoomAuthorityDelegation(delegationJSON); err != nil {
		return "", err
	}
	path, err := j.roomBlobPath(delegationBlobPrefix, canon.Digest(delegationJSON))
	if err != nil {
		return "", err
	}
	return j.writeChunk(path, roomDelegationSchema, delegationJSON)
}

func (j *Journal) loadDelegation(digest string) ([]byte, error) {
	path, err := j.roomBlobPath(delegationBlobPrefix, digest)
	if err != nil {
		return nil, err
	}
	raw, err := readChunk(path, roomDelegationSchema, digest)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxRoomDelegationBytes {
		return nil, errors.New("room authority delegation exceeds its bound")
	}
	return raw, nil
}

// stageMembership records the member set of one room epoch so the room can
// still judge membership at the epochs it can open after it moves on. It is
// named by the membership digest, which commits room, epoch and members.
func (j *Journal) stageMembership(membership room.Membership) error {
	digest, err := room.Digest(membership.RoomID, membership.Epoch, membership.Members)
	if err != nil {
		return err
	}
	if digest != membership.Digest {
		return errors.New("membership digest does not match its members")
	}
	path, err := j.roomBlobPath(membershipBlobPrefix, digest)
	if err != nil {
		return err
	}
	if existing, err := j.loadMembership(digest); err == nil {
		if existing.RoomID != membership.RoomID || existing.Epoch != membership.Epoch {
			return ErrRoomChunkDigest
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	encoded, err := json.Marshal(roomMembershipRecord{Schema: roomMembershipSchema, RoomID: membership.RoomID, Epoch: membership.Epoch, Members: membership.Members, Digest: digest})
	if err != nil {
		return err
	}
	return j.replace(path, encoded)
}

func (j *Journal) loadMembership(digest string) (room.Membership, error) {
	path, err := j.roomBlobPath(membershipBlobPrefix, digest)
	if err != nil {
		return room.Membership{}, err
	}
	raw, err := readRecordBytes(path)
	if err != nil {
		return room.Membership{}, err
	}
	var record roomMembershipRecord
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.Schema != roomMembershipSchema || record.Digest != digest {
		return room.Membership{}, errors.New("invalid room membership record")
	}
	recomputed, err := room.Digest(record.RoomID, record.Epoch, record.Members)
	if err != nil || recomputed != digest {
		return room.Membership{}, ErrRoomChunkDigest
	}
	return room.Membership{RoomID: record.RoomID, Epoch: record.Epoch, Members: record.Members, Digest: digest}, nil
}

// stageObject writes a room object as its outbox chunks and returns the chunk
// digests in order.
func (j *Journal) stageObject(object []byte) ([]string, error) {
	if len(object) == 0 || len(object) > MaxRoomObjectBytes {
		return nil, errors.New("invalid room object length")
	}
	chunks := splitChunks(object, RoomObjectChunkBytes)
	digests := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		path, err := j.roomObjectChunkPath(canon.Digest(chunk))
		if err != nil {
			return nil, err
		}
		digest, err := j.writeChunk(path, roomObjectChunkSchema, chunk)
		if err != nil {
			return nil, err
		}
		digests = append(digests, digest)
	}
	return digests, nil
}

// loadObject reassembles a room object from its chunks and checks the object
// digest the outbox names it by.
func (j *Journal) loadObject(objectDigest string, length uint32, chunkDigests []string) ([]byte, error) {
	if len(chunkDigests) == 0 || len(chunkDigests) > MaxRoomObjectChunks || length == 0 || length > MaxRoomObjectBytes {
		return nil, errors.New("invalid room object reference")
	}
	object := make([]byte, 0, length)
	for index, digest := range chunkDigests {
		path, err := j.roomObjectChunkPath(digest)
		if err != nil {
			return nil, err
		}
		chunk, err := readChunk(path, roomObjectChunkSchema, digest)
		if err != nil {
			return nil, err
		}
		if len(chunk) > RoomObjectChunkBytes || (index+1 < len(chunkDigests) && len(chunk) != RoomObjectChunkBytes) {
			return nil, errors.New("invalid room object chunk length")
		}
		object = append(object, chunk...)
	}
	if len(object) != int(length) || RoomObjectDigest(object) != objectDigest {
		return nil, ErrRoomChunkDigest
	}
	return object, nil
}
