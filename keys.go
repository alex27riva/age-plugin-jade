package main

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"filippo.io/nistec"
)

const (
	pluginName = "jade"

	// stanzaType is the recipient stanza type written into age headers.
	stanzaType = "jade-p256"

	// hkdfInfo domain-separates the wrapping key derivation.
	hkdfInfo = "age-plugin-jade/v1/" + stanzaType

	identityVersion = 1

	maxURILen = 191 // Jade rejects identities >= MAX_DISPLAY_MESSAGE_LEN (192)
	maxIndex  = 0x7fffffff
)

// jadeKey names one SLIP-0017 ECDH key on the device: an identity URI and
// index, plus the public key it derives to (so files can be matched, and the
// connected device verified, before asking the user to confirm anything).
type jadeKey struct {
	URI    string
	Index  uint32
	PubKey []byte // 33-byte compressed P-256 point
}

// Recipient payload: the 33-byte compressed P-256 public key.
//
// Identity payload (contains no secret material):
//
//	version (1) || index (4, big endian) || compressed pubkey (33) || URI
func (k *jadeKey) identityPayload() []byte {
	b := make([]byte, 0, 1+4+33+len(k.URI))
	b = append(b, identityVersion)
	b = binary.BigEndian.AppendUint32(b, k.Index)
	b = append(b, k.PubKey...)
	b = append(b, k.URI...)
	return b
}

func parseIdentityPayload(data []byte) (*jadeKey, error) {
	if len(data) < 1+4+33+7 {
		return nil, errors.New("identity too short")
	}
	if data[0] != identityVersion {
		return nil, fmt.Errorf("unsupported identity version %d", data[0])
	}
	k := &jadeKey{
		Index:  binary.BigEndian.Uint32(data[1:5]),
		PubKey: append([]byte(nil), data[5:38]...),
		URI:    string(data[38:]),
	}
	if err := validateURI(k.URI); err != nil {
		return nil, err
	}
	if k.Index > maxIndex {
		return nil, fmt.Errorf("index %d out of range", k.Index)
	}
	if _, err := decompress(k.PubKey); err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	return k, nil
}

func validateURI(uri string) error {
	if !strings.HasPrefix(uri, "ssh://") && !strings.HasPrefix(uri, "gpg://") {
		return fmt.Errorf("identity URI %q must start with ssh:// or gpg:// (a Jade firmware restriction)", uri)
	}
	if len(uri) <= len("ssh://") || len(uri) > maxURILen {
		return fmt.Errorf("identity URI must be 7 to %d characters long", maxURILen)
	}
	for _, c := range uri {
		if c < 0x20 || c > 0x7e {
			return errors.New("identity URI must be printable ASCII (Jade shows it on screen)")
		}
	}
	return nil
}

// tag identifies which recipient a stanza is for without revealing the
// public key: the first 4 bytes of SHA-256(compressed pubkey).
func tag(compressedPub []byte) []byte {
	h := sha256.Sum256(compressedPub)
	return h[:4]
}

func compress(uncompressed []byte) ([]byte, error) {
	if len(uncompressed) != 65 {
		return nil, fmt.Errorf("want 65-byte uncompressed point, got %d bytes", len(uncompressed))
	}
	p, err := nistec.NewP256Point().SetBytes(uncompressed)
	if err != nil {
		return nil, err
	}
	return p.BytesCompressed(), nil
}

func decompress(compressed []byte) ([]byte, error) {
	if len(compressed) != 33 {
		return nil, fmt.Errorf("want 33-byte compressed point, got %d bytes", len(compressed))
	}
	p, err := nistec.NewP256Point().SetBytes(compressed)
	if err != nil {
		return nil, err
	}
	return p.Bytes(), nil
}
