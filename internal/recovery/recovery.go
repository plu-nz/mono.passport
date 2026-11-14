// Package recovery seals the exported GPG private key with the master password
// so the vault repository can carry an encrypted copy of it.
//
// The export is already protected by GPG's own passphrase (S2K). This second
// layer uses Argon2id, which is far more expensive to brute-force, so an
// attacker who copies the repository faces a modern key derivation function.
package recovery

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Params are the Argon2id costs: Memory in KiB, Time in passes, Threads in lanes.
type Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
}

// DefaultParams take about half a second on a modest laptop (256 MiB, 3 passes).
var DefaultParams = Params{Memory: 256 * 1024, Time: 3, Threads: 4}

// Bounds applied when opening a file, so a hostile file cannot make Passage
// allocate unbounded memory or spin for minutes before failing.
const (
	minMemory  = 8 * 1024
	maxMemory  = 1024 * 1024
	maxTime    = 10
	maxThreads = 16
	maxSize    = 1 << 20
	saltSize   = 16
	keySize    = chacha20poly1305.KeySize
)

// ErrWrongPassword means the password does not open the file, or the file was changed.
var ErrWrongPassword = errors.New("Wrong master password or damaged recovery file")

var fingerprintPattern = regexp.MustCompile(`^[A-F0-9]{40}([A-F0-9]{24})?$`)

// header is authenticated as additional data, so changing any field breaks Open.
type header struct {
	Version     int    `json:"v"`
	KDF         string `json:"kdf"`
	Memory      uint32 `json:"m"`
	Time        uint32 `json:"t"`
	Threads     uint8  `json:"p"`
	Salt        []byte `json:"salt"`
	Nonce       []byte `json:"nonce"`
	Fingerprint string `json:"fpr"`
}

type file struct {
	header
	Ciphertext []byte `json:"ct"`
}

// Seal encrypts plaintext (the armored secret key) for the given key fingerprint.
func Seal(password []byte, fingerprint string, plaintext []byte) ([]byte, error) {
	return SealWith(DefaultParams, password, fingerprint, plaintext)
}

// SealWith is Seal with explicit Argon2id costs; tests use cheaper ones.
func SealWith(params Params, password []byte, fingerprint string, plaintext []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("Master password is empty")
	}
	h := header{Version: 1, KDF: "argon2id", Memory: params.Memory, Time: params.Time, Threads: params.Threads, Fingerprint: fingerprint, Salt: make([]byte, saltSize), Nonce: make([]byte, chacha20poly1305.NonceSizeX)}
	if err := h.validate(); err != nil {
		return nil, err
	}
	if _, err := rand.Read(h.Salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(h.Nonce); err != nil {
		return nil, err
	}
	aead, err := h.aead(password)
	if err != nil {
		return nil, err
	}
	ad, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	return json.Marshal(file{header: h, Ciphertext: aead.Seal(nil, h.Nonce, plaintext, ad)})
}

// Open decrypts a sealed file and returns the plaintext and the key fingerprint it was made for.
func Open(password []byte, blob []byte) ([]byte, string, error) {
	if len(blob) > maxSize {
		return nil, "", errors.New("Recovery file is too large")
	}
	var f file
	if err := json.Unmarshal(blob, &f); err != nil {
		return nil, "", errors.New("Recovery file is not readable")
	}
	if err := f.validate(); err != nil {
		return nil, "", err
	}
	aead, err := f.aead(password)
	if err != nil {
		return nil, "", err
	}
	ad, err := json.Marshal(f.header)
	if err != nil {
		return nil, "", err
	}
	plaintext, err := aead.Open(nil, f.Nonce, f.Ciphertext, ad)
	if err != nil {
		return nil, "", ErrWrongPassword
	}
	return plaintext, f.Fingerprint, nil
}

func (h header) validate() error {
	switch {
	case h.Version != 1:
		return fmt.Errorf("Unsupported recovery file version %d", h.Version)
	case h.KDF != "argon2id":
		return errors.New("Unsupported recovery file key derivation")
	case h.Memory < minMemory || h.Memory > maxMemory || h.Time < 1 || h.Time > maxTime || h.Threads < 1 || h.Threads > maxThreads:
		return errors.New("Recovery file has out-of-range key derivation costs")
	case len(h.Salt) != saltSize || len(h.Nonce) != chacha20poly1305.NonceSizeX:
		return errors.New("Recovery file has an invalid salt or nonce")
	case !fingerprintPattern.MatchString(h.Fingerprint):
		return errors.New("Recovery file has an invalid key fingerprint")
	}
	return nil
}

func (h header) aead(password []byte) (cipher.AEAD, error) {
	if len(password) == 0 {
		return nil, errors.New("Master password is empty")
	}
	key := argon2.IDKey(password, h.Salt, h.Time, h.Memory, h.Threads, keySize)
	defer clear(key)
	return chacha20poly1305.NewX(key)
}

