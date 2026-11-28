package radius

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/lanrith/router-policy-agent/internal/hostfs"
	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

const checkpointFile = "accounting-v1.json"
const checkpointLimit = 16 << 20
const exactClosedLimit = 4096
const retiredBytes = 512 << 10

var errGap = errors.New("radius: journal cursor continuity lost")

type storedCheckpoint struct {
	Sum   string
	State json.RawMessage
}

// The checkpoint is local to the current kernel boot. The session timeline uses
// the journal's monotonic receipt clock, with NAS delay deducted. WallOriginal
// caps the deadline separately, even after a correction of the router clock.
type checkpoint struct {
	Scope     string
	Cursor    string
	Anchor    string
	Cutoff    int64
	Monotonic int64
	States    map[string]*sessionState
	Closed    map[string]bool
	Retired   []byte
}

func newCheckpoint(scope string) checkpoint {
	return checkpoint{Scope: scope, States: make(map[string]*sessionState), Closed: make(map[string]bool)}
}

func readCheckpoint(ctx context.Context, root *os.Root, owner uint32, scope string) (checkpoint, error) {
	file, err := hostfs.OpenRegular(ctx, root, hostfs.FileOptions{Name: checkpointFile, OwnerUID: owner, MaximumSize: checkpointLimit})
	if errors.Is(err, os.ErrNotExist) {
		return newCheckpoint(scope), nil
	}
	if err != nil {
		return checkpoint{}, err
	}
	data, err := io.ReadAll(io.LimitReader(file, checkpointLimit+1))
	if err := errors.Join(err, file.Close()); err != nil {
		return checkpoint{}, err
	}
	var stored storedCheckpoint
	if strictjson.Decode(data, &stored, checkpointLimit) != nil || digest(string(stored.State)) != stored.Sum {
		return checkpoint{}, errGap
	}
	var cp checkpoint
	if strictjson.Decode(stored.State, &cp, checkpointLimit) != nil || cp.States == nil || cp.Closed == nil || len(cp.States) > maximumSessions || len(cp.Closed) > exactClosedLimit || len(cp.Retired) != 0 && len(cp.Retired) != retiredBytes {
		return checkpoint{}, errGap
	}
	if cp.Scope != scope {
		return newCheckpoint(scope), nil
	}
	for key, state := range cp.States {
		if len(key) != 64 || state == nil || len(state.First.Key) != 64 || state.First.MAC == "" ||
			state.Last.MAC != state.First.MAC || state.Last.Key != state.First.Key || state.Last.WallOriginal.IsZero() ||
			state.First.Original.IsZero() || state.Last.Original.IsZero() || cp.Closed[key] && !state.Conflict {
			return checkpoint{}, errGap
		}
	}
	if len(cp.Cursor) > 2048 || cp.Cursor != "" && len(cp.Anchor) != 64 || cp.Monotonic < 0 || cp.Cutoff < 0 {
		return checkpoint{}, errGap
	}
	return cp, nil
}

func (cp checkpoint) save(ctx context.Context, root *os.Root, owner uint32) error {
	state, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	data, err := json.Marshal(storedCheckpoint{Sum: digest(string(state)), State: state})
	if err != nil {
		return err
	}
	return writePrivate(ctx, root, checkpointFile, data, owner, checkpointLimit)
}

func monotonicNow() (time.Time, error) {
	var stamp syscall.Timespec
	const clockMonotonic = 1 // Linux CLOCK_MONOTONIC, as used by the system journal.
	_, _, err := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockMonotonic, uintptr(unsafe.Pointer(&stamp)), 0)
	if err != 0 {
		return time.Time{}, err
	}
	return time.Unix(stamp.Sec, stamp.Nsec).UTC(), nil
}

func (cp *checkpoint) advance(data []byte, scope Scope, mono time.Time, discard bool) error {
	first := true
	for line := range bytes.Lines(data) {
		var stamp struct {
			Cursor string `json:"__CURSOR"`
			Mono   string `json:"__MONOTONIC_TIMESTAMP"`
			Wall   string `json:"__REALTIME_TIMESTAMP"`
		}
		if json.Unmarshal(line, &stamp) != nil || len(stamp.Cursor) == 0 || len(stamp.Cursor) > 2048 || strings.ContainsAny(stamp.Cursor, "\r\n\x00") {
			return errAccounting
		}
		us, err := unsigned(stamp.Mono, uint64(math.MaxInt64/int64(time.Microsecond)))
		if err != nil || int64(us) > mono.UnixMicro() {
			return errAccounting
		}
		receipt, err := unsigned(stamp.Wall, 9999999999999999)
		if err != nil {
			return errAccounting
		}
		hash := digest(string(line))
		if first && cp.Cursor != "" {
			if stamp.Cursor != cp.Cursor || hash != cp.Anchor || int64(us) != cp.Monotonic {
				return errGap
			}
			first = false
			continue
		}
		first = false
		if int64(us) < cp.Monotonic || cp.Cursor == stamp.Cursor {
			return errGap
		}
		wall := time.UnixMicro(int64(receipt)).UTC()
		item, err := decodeEntry(bytes.TrimSpace(line), scope, wall)
		if err != nil {
			return err
		}
		if !discard {
			item.Original = time.UnixMicro(int64(us)).UTC().Add(-wall.Sub(item.Original))
			if err := cp.apply(item, mono); err != nil {
				return err
			}
		}

		cp.Cursor, cp.Anchor, cp.Monotonic = stamp.Cursor, hash, int64(us)
	}
	if first && cp.Cursor != "" {
		return errGap
	}
	return nil
}

func (cp *checkpoint) apply(item event, mono time.Time) error {
	key := item.Key
	if item.Status == "Stop" {
		cp.retire(key)
		return nil
	}
	if cp.Cutoff != 0 && item.Original.UnixMicro() < cp.Cutoff {
		item.UnknownAge = true
	}
	state := cp.States[key]
	conflict := state != nil && state.First.MAC != item.MAC
	if conflict {
		// Preserve both attributable owners and their reported address claims.
		// Neither association can qualify while the key is ambiguous.
		state.Conflict = true
		key = digest("conflicting-owner", key, item.MAC)
		state = cp.States[key]
	}
	if state == nil {
		if len(cp.States) >= maximumSessions {
			for oldKey, old := range cp.States {
				if !mono.Before(old.Last.Original.Add(Freshness)) && !mono.Before(old.Uncertain.Original.Add(Freshness)) {
					cp.retire(oldKey)
				}
			}
		}
		if len(cp.States) >= maximumSessions {
			return errBudget
		}
		// Keep even a retired or uncertain identity's fresh address claims as
		// negative evidence. A filter collision can withhold only that identity.
		state = &sessionState{First: item, Last: item, Conflict: conflict || cp.wasClosed(key)}
		cp.States[key] = state
	}
	return state.apply(item)
}

// Keep exact tombstones for small boots. Beyond that bound use a fixed
// Bloom filter. It has no false negatives and affects only attempts to open
// a new association; currently verified owners retain their original anchors.
func (cp *checkpoint) retire(key string) {
	delete(cp.States, key)
	if len(cp.Retired) == 0 && len(cp.Closed) < exactClosedLimit {
		cp.Closed[key] = true
		return
	}
	if len(cp.Retired) == 0 {
		cp.Retired = make([]byte, retiredBytes)
		for id := range cp.Closed {
			cp.remember(id)
		}
		clear(cp.Closed)
	}
	cp.remember(key)
}

func retirementBits(key string) [5]uint32 {
	hash := sha256.Sum256([]byte(key))
	var indices [5]uint32
	for i := range indices {
		indices[i] = binary.LittleEndian.Uint32(hash[4*i:]) % (retiredBytes * 8)
	}
	return indices
}

func (cp *checkpoint) remember(key string) {
	for _, bit := range retirementBits(key) {
		cp.Retired[bit/8] |= 1 << (bit % 8)
	}
}

func (cp *checkpoint) wasClosed(key string) bool {
	if len(cp.Retired) == 0 {
		return cp.Closed[key]
	}
	for _, bit := range retirementBits(key) {
		if cp.Retired[bit/8]&(1<<(bit%8)) == 0 {
			return false
		}
	}
	return true
}

func (cp *checkpoint) observe(wall, offset time.Time) Observation {
	mono := time.Unix(0, wall.Sub(offset).Nanoseconds()).UTC()
	observation := current(cp.States, mono)
	observation.ObservedAt = wall
	// Use one conversion origin for the entire scan. Re-reading an anchor can
	// only shorten its wall deadline, never renew it.
	states := make(map[string]*sessionState, len(observation.Sessions))
	for _, state := range cp.States {
		if state.Started {
			states[digest(state.First.Key, strconv.FormatInt(state.First.Original.Unix(), 10))] = state
		}
	}
	observation.Sessions = slices.DeleteFunc(observation.Sessions, func(session Session) bool {
		state := states[session.AssociationID]
		return state == nil || !wall.Before(state.Last.WallOriginal.Add(Freshness))
	})
	for i := range observation.Sessions {
		session := &observation.Sessions[i]
		state := states[session.AssociationID]
		session.ObservedAt = offset.Add(session.ObservedAt.Sub(time.Unix(0, 0))).UTC()
		if state.Last.WallOriginal.Before(session.ObservedAt) {
			session.ObservedAt = state.Last.WallOriginal
		}
		session.StartedAt = state.First.WallOriginal
		if session.ObservedAt.Before(session.StartedAt) {
			session.StartedAt = session.ObservedAt
		}
		session.ValidUntil = session.ObservedAt.Add(Freshness)
	}
	return observation
}

type journalCheckpoint struct {
	root    *os.Root
	owner   uint32
	cp      checkpoint
	offset  time.Time
	options JournalOptions
}

const journalBatchSize = 256

func (stream *journalCheckpoint) capture(ctx context.Context) (history, error) {
	parent := stream.cp.Anchor
	for {
		cursor := ""
		if stream.cp.Cursor != "" {
			cursor = "--cursor=" + stream.cp.Cursor
		}
		captured, err := captureJournal(ctx, stream.options, cursor, "--lines=+"+strconv.Itoa(journalBatchSize), true)
		if err != nil {
			if cursor != "" && !errors.Is(err, errBudget) && ctx.Err() == nil {
				return history{}, stream.reset(ctx)
			}
			return history{}, err
		}
		mono, err := monotonicNow()
		if err != nil {
			return history{}, err
		}
		prev := stream.cp.Anchor
		if err := stream.cp.advance(captured.data, captured.scope, mono, false); err != nil {
			if errors.Is(err, errGap) {
				return history{}, stream.reset(ctx)
			}
			return history{}, err
		}
		if stream.cp.Anchor != prev {
			if err := stream.cp.save(ctx, stream.root, stream.owner); err != nil {
				return history{}, err
			}
		}
		// Commit each bounded page, including when the collection deadline
		// interrupts catch-up. Only the tail can yield a publishable snapshot.
		if bytes.Count(captured.data, []byte{'\n'}) == journalBatchSize {
			continue
		}
		observation := stream.cp.observe(captured.observedAt, stream.offset)
		captured.data = []byte(stream.cp.Anchor)
		captured.parent = parent
		captured.observation = &observation
		return captured, nil
	}
}

// reset establishes an authenticated high-water mark. No record at or before
// the gap can become a new association, including a delayed duplicate Start.
func (stream *journalCheckpoint) reset(ctx context.Context) error {
	head, err := captureJournal(ctx, stream.options, "", "--lines=1", true)
	if err != nil {
		return err
	}
	mono, err := monotonicNow()
	if err != nil {
		return err
	}
	fresh := newCheckpoint(stream.cp.Scope)
	fresh.Closed, fresh.Retired = stream.cp.Closed, stream.cp.Retired
	fresh.Cutoff = mono.UnixMicro()
	if err := fresh.advance(head.data, head.scope, mono, true); err != nil {
		return err
	}
	if err := fresh.save(ctx, stream.root, stream.owner); err != nil {
		return err
	}
	stream.cp = fresh
	return errGap
}
