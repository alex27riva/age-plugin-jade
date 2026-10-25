package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/alex27riva/age-plugin-jade/internal/mockjade"
	"github.com/alex27riva/age-plugin-jade/jade"
)

// softDevice holds the private key in software, to test the age logic alone.
type softDevice struct{ priv *ecdh.PrivateKey }

func (d softDevice) SharedKey(_ *jadeKey, pub []byte) ([]byte, error) {
	p, err := ecdh.P256().NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return d.priv.ECDH(p)
}

func newSoftKey(t *testing.T) (*jadeKey, softDevice) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := compress(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return &jadeKey{URI: "ssh://test@jade", PubKey: pk}, softDevice{priv}
}

func encryptDecrypt(t *testing.T, r age.Recipient, id age.Identity) error {
	t.Helper()
	msg := []byte("attack at dawn")
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(msg)
	w.Close()
	rd, err := age.Decrypt(&buf, id)
	if err != nil {
		return err
	}
	got, err := io.ReadAll(rd)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
	return nil
}

func TestSoftwareRoundTrip(t *testing.T) {
	k, dev := newSoftKey(t)
	r, err := newRecipient(k.PubKey)
	if err != nil {
		t.Fatal(err)
	}
	id := &Identity{key: k, device: func() (Device, error) { return dev, nil }}
	if err := encryptDecrypt(t, r, id); err != nil {
		t.Fatal(err)
	}
}

func TestOtherKeyNeverTouchesDevice(t *testing.T) {
	k1, _ := newSoftKey(t)
	k2, _ := newSoftKey(t)
	r, _ := newRecipient(k1.PubKey)
	id := &Identity{key: k2, device: func() (Device, error) {
		t.Fatal("device opened for a non-matching stanza")
		return nil, nil
	}}
	err := encryptDecrypt(t, r, id)
	var noMatch *age.NoIdentityMatchError
	if !errors.As(err, &noMatch) {
		t.Fatalf("got %v, want NoIdentityMatchError", err)
	}
}

func TestEncodings(t *testing.T) {
	k, _ := newSoftKey(t)
	k.Index = 42
	s := plugin.EncodeIdentity(pluginName, k.identityPayload())
	if !strings.HasPrefix(s, "AGE-PLUGIN-JADE-1") {
		t.Fatalf("identity %q", s)
	}
	name, data, err := plugin.ParseIdentity(s)
	if err != nil || name != pluginName {
		t.Fatal(name, err)
	}
	k2, err := parseIdentityPayload(data)
	if err != nil {
		t.Fatal(err)
	}
	if k2.URI != k.URI || k2.Index != 42 || !bytes.Equal(k2.PubKey, k.PubKey) {
		t.Fatalf("round trip mismatch: %+v", k2)
	}
	if r := encodeRecipient(k.PubKey); !strings.HasPrefix(r, "age1jade1") {
		t.Fatalf("recipient %q", r)
	}
	for _, bad := range []string{"https://x", "ssh://", "ssh://\x01", "ssh://" + strings.Repeat("a", 200)} {
		if validateURI(bad) == nil {
			t.Errorf("validateURI(%q) succeeded", bad)
		}
	}
	if _, err := newRecipient(make([]byte, 33)); err == nil {
		t.Error("accepted invalid point")
	}
}

func startMock(t *testing.T, passphrase string) (*mockjade.Jade, string) {
	t.Helper()
	j := mockjade.New(mockjade.TestMnemonic, passphrase)
	j.Logf = t.Logf
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go j.Serve(l)
	t.Cleanup(func() { l.Close(); j.Close() })
	return j, "tcp:" + l.Addr().String()
}

func session(port string) *deviceSession {
	return &deviceSession{port: port, msg: func(string) {}}
}

func TestMockDevice(t *testing.T) {
	j, port := startMock(t, "")

	gen := session(port)
	pk, err := gen.PubKey("ssh://age@jade", 0)
	gen.Close()
	if err != nil {
		t.Fatal(err)
	}
	k := &jadeKey{URI: "ssh://age@jade", PubKey: pk}
	r, _ := newRecipient(pk)

	sess := session(port)
	defer sess.Close()
	id := &Identity{key: k, device: func() (Device, error) { return sess, nil }}
	if err := encryptDecrypt(t, r, id); err != nil {
		t.Fatal(err)
	}
	if j.Confirmations != 1 {
		t.Fatalf("confirmations = %d, want 1", j.Confirmations)
	}

	// Deterministic: same URI/index gives the same key; index changes it.
	again, _ := session(port).PubKey("ssh://age@jade", 0)
	other, _ := session(port).PubKey("ssh://age@jade", 1)
	if !bytes.Equal(again, pk) || bytes.Equal(other, pk) {
		t.Fatal("derivation not deterministic per (uri, index)")
	}

	j.Decline = true
	err = encryptDecrypt(t, r, id)
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("decline: got %v", err)
	}
}

func TestMockWrongPassphrase(t *testing.T) {
	_, port1 := startMock(t, "")
	j2, port2 := startMock(t, "different passphrase")

	pk, err := session(port1).PubKey("ssh://age@jade", 0)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := newRecipient(pk)
	sess := session(port2)
	defer sess.Close()
	id := &Identity{key: &jadeKey{URI: "ssh://age@jade", PubKey: pk},
		device: func() (Device, error) { return sess, nil }}
	err = encryptDecrypt(t, r, id)
	if err == nil || !strings.Contains(err.Error(), "different key") {
		t.Fatalf("got %v", err)
	}
	if j2.Confirmations != 0 {
		t.Fatal("user was asked to confirm on the wrong device")
	}
}

func TestMockNetworkAutoDetect(t *testing.T) {
	j, port := startMock(t, "")
	j.Networks = "TEST"
	if _, err := session(port).PubKey("ssh://age@jade", 0); err != nil {
		t.Fatal(err)
	}
}

func TestMockNetworkMismatch(t *testing.T) {
	j, port := startMock(t, "")
	j.Networks = "TEST"
	sess := session(port)
	sess.network = "mainnet"
	_, err := sess.PubKey("ssh://age@jade", 0)
	var je *jade.Error
	if !errors.As(err, &je) || je.Code != jade.CodeNetworkMismatch || !strings.Contains(err.Error(), "set it to testnet") {
		t.Fatalf("got %v", err)
	}
}
