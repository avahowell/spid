package sentinel

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

// Sentinel is a scanner that can be used to securely detect and record file
// integrity changes for a set of files.
type Sentinel struct {
	WatchFiles   []string
	KnownObjects map[string]checksum
	PriorScans   []scan
}

// Event defines a file integrity event.
type event struct {
	Evtype       string
	OrigChecksum checksum
	NewChecksum  checksum
	File         string
}

// scan stores the information from a single sentinal scan event.
type scan struct {
	Timestamp time.Time
	Events    []event
}

// Config defines the configuration for a sentinel.
type Config struct {
	WatchFiles []string
}

// SentinelFile stores the data used to encode a sentinel.
type SentinelFile struct {
	Data  []byte
	Nonce [24]byte
	Salt  [24]byte
}

type checksum string

const evCreate = "EV_CREATE"
const evModify = "EV_MODIFY"
const (
	scryptN = 16384
	scryptP = 1
	scryptR = 8
	keyLen  = 32
)

// checksumFile returns the sha256 checksum of the file at the provided path.
func checksumFile(path string) (checksum, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	_, err = io.Copy(h, f)
	if err != nil {
		return "", err
	}

	return checksum(hex.EncodeToString(h.Sum(nil))), nil
}

// New creates a new sentinel using the options specified in config.
func New(config Config) *Sentinel {
	return &Sentinel{
		WatchFiles:   config.WatchFiles,
		KnownObjects: make(map[string]checksum),
	}
}

// Scan checks the files watched by the sentinel and returns relevant integrity
// events.
func (s *Sentinel) Scan() ([]event, error) {
	var evs []event
	for _, wf := range s.WatchFiles {
		checksum, err := checksumFile(wf)
		if err != nil {
			return nil, err
		}
		knownChecksum, seen := s.KnownObjects[wf]
		if !seen {
			evs = append(evs, event{Evtype: evCreate, NewChecksum: checksum, File: wf})
		} else if knownChecksum != checksum {
			evs = append(evs, event{Evtype: evModify, OrigChecksum: knownChecksum, NewChecksum: checksum, File: wf})
		}
		s.KnownObjects[wf] = checksum
	}
	s.PriorScans = append(s.PriorScans, scan{
		Timestamp: time.Now(),
		Events:    evs,
	})
	return evs, nil
}

// Save writes the sentinel to the path supplied in `path`, encrypting the
// sentinel using the password provided to `password.
func (s *Sentinel) Save(path string, password string) error {
	var nonce, salt [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return err
	}
	_, err = io.ReadFull(rand.Reader, salt[:])
	if err != nil {
		return err
	}
	var secret [32]byte
	key, err := scrypt.Key([]byte(password), salt[:], scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return err
	}
	copy(secret[:], key)

	var encoded bytes.Buffer
	err = gob.NewEncoder(&encoded).Encode(s)
	if err != nil {
		return err
	}

	data := secretbox.Seal(nonce[:], encoded.Bytes(), &nonce, &secret)
	out := SentinelFile{Data: data, Nonce: nonce, Salt: salt}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return gob.NewEncoder(f).Encode(out)
}

// Open loads a sentinel from disk using the supplied `path` and `password`.
func Open(path string, password string) (*Sentinel, error) {
	var in SentinelFile
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	err = gob.NewDecoder(f).Decode(&in)
	if err != nil {
		return nil, err
	}
	var secret [32]byte
	key, err := scrypt.Key([]byte(password), in.Salt[:], scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return nil, err
	}
	copy(secret[:], key)
	decryptedData, success := secretbox.Open([]byte{}, in.Data[len(in.Nonce):], &in.Nonce, &secret)
	if !success {
		return nil, errors.New("could not decrypt sentinel")
	}
	var s Sentinel
	err = gob.NewDecoder(bytes.NewBuffer(decryptedData)).Decode(&s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}
