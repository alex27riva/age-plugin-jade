package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/alex27riva/age-plugin-jade/jade"
)

// deviceSession lazily connects to and unlocks a Jade, then serves ECDH
// requests. One session is shared by all identities in a plugin run.
type deviceSession struct {
	port    string
	network string
	msg     func(string) // how to show progress to the user

	c        *jade.Client
	verified map[string]bool
}

func (d *deviceSession) Close() {
	if d.c != nil {
		d.c.Close()
	}
}

func (d *deviceSession) connect() error {
	if d.c != nil {
		return nil
	}
	c, err := jade.Open(d.port)
	if err != nil {
		return err
	}
	info, err := c.VersionInfo()
	if err != nil {
		c.Close()
		return fmt.Errorf("talking to Jade: %w", err)
	}
	switch info.State {
	case "UNINIT":
		c.Close()
		return errors.New("this Jade has no wallet set up")
	case "LOCKED", "UNSAVED":
		d.msg("enter your PIN on the Jade")
	}
	if err := c.Auth(d.network); err != nil {
		c.Close()
		var je *jade.Error
		if errors.As(err, &je) && je.Code == jade.CodeNetworkMismatch {
			return fmt.Errorf("%w (this Jade is locked to %s networks: try --network testnet or JADE_NETWORK=testnet)", err, info.Networks)
		}
		return fmt.Errorf("unlocking Jade: %w", err)
	}
	d.c = c
	d.verified = map[string]bool{}
	return nil
}

func keyID(k *jadeKey) string { return fmt.Sprintf("%d:%s", k.Index, k.URI) }

// PubKey fetches the compressed SLIP-0017 public key for k (no confirmation).
func (d *deviceSession) PubKey(uri string, index uint32) ([]byte, error) {
	if err := d.connect(); err != nil {
		return nil, err
	}
	u, err := d.c.IdentityPubKey(uri, index)
	if err != nil {
		return nil, explain(err)
	}
	return compress(u)
}

func (d *deviceSession) SharedKey(k *jadeKey, theirPub []byte) ([]byte, error) {
	if err := d.connect(); err != nil {
		return nil, err
	}
	// Check the connected device actually holds this key before prompting,
	// so a wrong seed or passphrase gives a clear error instead of a
	// confirmation followed by a failed decryption.
	if !d.verified[keyID(k)] {
		pk, err := d.PubKey(k.URI, k.Index)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(pk, k.PubKey) {
			return nil, fmt.Errorf("this Jade derives a different key for %q (index %d): wrong device, seed or BIP39 passphrase", k.URI, k.Index)
		}
		d.verified[keyID(k)] = true
	}

	d.msg(fmt.Sprintf("confirm on your Jade to decrypt (identity %s)", k.URI))
	s, err := d.c.IdentitySharedKey(k.URI, k.Index, theirPub)
	if err != nil {
		if jade.IsUserCancelled(err) {
			return nil, errors.New("decryption declined on the Jade")
		}
		return nil, explain(err)
	}
	return s, nil
}

func explain(err error) error {
	var je *jade.Error
	if !errors.As(err, &je) {
		return err
	}
	switch {
	case je.Code == jade.CodeUnknownMethod:
		return fmt.Errorf("%w: update the Jade firmware to a version with SSH/GPG identity support", err)
	case strings.Contains(je.Message, "requires resetting"):
		return fmt.Errorf("%w: this wallet was loaded without storing the seed; wipe and restore the Jade from its mnemonic to use identity features", err)
	}
	return err
}
