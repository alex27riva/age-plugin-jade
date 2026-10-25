package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
)

// Wire format of a recipient stanza:
//
//	-> jade-p256 <tag> <epk>
//	<ChaCha20-Poly1305(wrapKey, nonce=0, fileKey)>
//
// tag     = base64(SHA-256(recipient pubkey)[:4])
// epk     = base64(compressed ephemeral P-256 public key)
// wrapKey = HKDF-SHA-256(ikm  = ECDH(eph, recipient).X,
//                        salt = epk || recipient pubkey,
//                        info = "age-plugin-jade/v1/jade-p256")
//
// This mirrors age-plugin-yubikey's piv-p256 construction; the only
// difference is that the decrypting side's ECDH runs on the Jade.

var b64 = base64.RawStdEncoding

const fileKeySize = 16

func wrapKey(shared, epk, recipientPub []byte) ([]byte, error) {
	salt := make([]byte, 0, len(epk)+len(recipientPub))
	salt = append(salt, epk...)
	salt = append(salt, recipientPub...)
	return hkdf.Key(sha256.New, shared, salt, hkdfInfo, chacha20poly1305.KeySize)
}

// Recipient encrypts to a Jade key. It never touches the device.
type Recipient struct {
	pub *ecdh.PublicKey
	pkc []byte // compressed
}

var _ age.Recipient = &Recipient{}

func newRecipient(compressedPub []byte) (*Recipient, error) {
	u, err := decompress(compressedPub)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient: %w", err)
	}
	pub, err := ecdh.P256().NewPublicKey(u)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient: %w", err)
	}
	return &Recipient{pub: pub, pkc: append([]byte(nil), compressedPub...)}, nil
}

func (r *Recipient) String() string { return encodeRecipient(r.pkc) }

func (r *Recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(r.pub)
	if err != nil {
		return nil, err
	}
	epk, err := compress(eph.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	key, err := wrapKey(shared, epk, r.pkc)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	body := aead.Seal(nil, make([]byte, chacha20poly1305.NonceSize), fileKey, nil)
	return []*age.Stanza{{
		Type: stanzaType,
		Args: []string{b64.EncodeToString(tag(r.pkc)), b64.EncodeToString(epk)},
		Body: body,
	}}, nil
}

// Device performs the private half of the ECDH. *deviceSession implements it
// with a real Jade; tests substitute a software key.
type Device interface {
	SharedKey(k *jadeKey, theirUncompressedPub []byte) ([]byte, error)
}

// Identity decrypts files encrypted to a Jade key.
type Identity struct {
	key    *jadeKey
	device func() (Device, error) // opened lazily, only for matching stanzas
}

var _ age.Identity = &Identity{}

func (i *Identity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	myTag := tag(i.key.PubKey)
	for _, s := range stanzas {
		if s.Type != stanzaType {
			continue
		}
		if len(s.Args) != 2 {
			return nil, fmt.Errorf("%s stanza: want 2 arguments, got %d", stanzaType, len(s.Args))
		}
		t, err := b64.DecodeString(s.Args[0])
		if err != nil || len(t) != 4 {
			return nil, fmt.Errorf("%s stanza: malformed tag", stanzaType)
		}
		if !bytes.Equal(t, myTag) {
			continue // for a different Jade key
		}
		epk, err := b64.DecodeString(s.Args[1])
		if err != nil {
			return nil, fmt.Errorf("%s stanza: malformed ephemeral key", stanzaType)
		}
		epkU, err := decompress(epk)
		if err != nil {
			return nil, fmt.Errorf("%s stanza: invalid ephemeral key: %w", stanzaType, err)
		}
		if len(s.Body) != fileKeySize+chacha20poly1305.Overhead {
			return nil, fmt.Errorf("%s stanza: body has wrong length %d", stanzaType, len(s.Body))
		}

		dev, err := i.device()
		if err != nil {
			return nil, err
		}
		shared, err := dev.SharedKey(i.key, epkU)
		if err != nil {
			return nil, err
		}
		key, err := wrapKey(shared, epk, i.key.PubKey)
		if err != nil {
			return nil, err
		}
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		fileKey, err := aead.Open(nil, make([]byte, chacha20poly1305.NonceSize), s.Body, nil)
		if err != nil {
			// The tag matched, so this is almost certainly a 4-byte tag
			// collision with another Jade key; keep looking.
			continue
		}
		return fileKey, nil
	}
	return nil, age.ErrIncorrectIdentity
}
