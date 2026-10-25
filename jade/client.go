package jade

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Error codes from Jade's main/utils/cbor_rpc.h.
const (
	CodeInvalidRequest  = -32600
	CodeUnknownMethod   = -32601
	CodeBadParameters   = -32602
	CodeInternalError   = -32603
	CodeUserCancelled   = -32000
	CodeProtocolError   = -32001
	CodeHWLocked        = -32002
	CodeNetworkMismatch = -32003
)

// Error is an error reply from the device.
type Error struct {
	Method  string
	Code    int
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("jade: %s: %s (code %d)", e.Method, e.Message, e.Code)
}

// IsUserCancelled reports whether err is the user declining on the device.
func IsUserCancelled(err error) bool {
	var je *Error
	return errors.As(err, &je) && je.Code == CodeUserCancelled
}

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	var err error
	if encMode, err = cbor.CanonicalEncOptions().EncMode(); err != nil {
		panic(err)
	}
	// Decode untyped maps as map[string]any so they round-trip through JSON
	// (needed for the PIN server relay).
	if decMode, err = (cbor.DecOptions{
		DefaultMapType:  reflect.TypeOf(map[string]any(nil)),
		MaxNestedLevels: 32,
	}).DecMode(); err != nil {
		panic(err)
	}
}

// Client talks to one Jade. It is not safe for concurrent use.
type Client struct {
	rw  io.ReadWriteCloser
	dec *cbor.Decoder

	// Log, if set, receives the device's own log lines (only emitted by
	// debug firmware builds).
	Log func(string)
}

func newClient(rw io.ReadWriteCloser) *Client {
	return &Client{rw: rw, dec: decMode.NewDecoder(bufio.NewReader(rw))}
}

// Close closes the connection. It does not lock the device.
func (c *Client) Close() error { return c.rw.Close() }

type request struct {
	ID     string `cbor:"id"`
	Method string `cbor:"method"`
	Params any    `cbor:"params,omitempty"`
}

type rpcError struct {
	Code    int    `cbor:"code"`
	Message string `cbor:"message"`
}

type response struct {
	ID     *string         `cbor:"id"`
	Result cbor.RawMessage `cbor:"result"`
	Error  *rpcError       `cbor:"error"`
	Log    any             `cbor:"log"`
}

func newID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// call sends one request and returns the raw result of its reply. Replies to
// other ids (stale replies from an interrupted previous session) are skipped.
func (c *Client) call(method string, params any) (cbor.RawMessage, error) {
	id := newID()
	msg, err := encMode.Marshal(request{ID: id, Method: method, Params: params})
	if err != nil {
		return nil, fmt.Errorf("jade: encoding %s: %w", method, err)
	}
	if _, err := c.rw.Write(msg); err != nil {
		return nil, fmt.Errorf("jade: writing %s: %w", method, err)
	}
	for {
		var r response
		if err := c.dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("jade: reading %s reply: %w", method, err)
		}
		if r.ID == nil {
			if r.Log != nil && c.Log != nil {
				c.Log(fmt.Sprint(logText(r.Log)))
			}
			continue
		}
		if *r.ID != id {
			continue
		}
		if r.Error != nil {
			return nil, &Error{Method: method, Code: r.Error.Code, Message: r.Error.Message}
		}
		if r.Result == nil {
			return nil, fmt.Errorf("jade: %s: reply has neither result nor error", method)
		}
		return r.Result, nil
	}
}

func logText(v any) any {
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return v
}

// Ping checks the device is responsive. It returns 0 if idle, 1 if busy with
// a client message, 2 if the user is navigating the menus.
func (c *Client) Ping() (int, error) {
	raw, err := c.call("ping", nil)
	if err != nil {
		return 0, err
	}
	var v int
	err = decMode.Unmarshal(raw, &v)
	return v, err
}

// VersionInfo is the subset of get_version_info used here.
type VersionInfo struct {
	Version   string `cbor:"JADE_VERSION"`
	State     string `cbor:"JADE_STATE"`
	Networks  string `cbor:"JADE_NETWORKS"`
	BoardType string `cbor:"BOARD_TYPE"`
	HasPIN    bool   `cbor:"JADE_HAS_PIN"`
}

func (c *Client) VersionInfo() (*VersionInfo, error) {
	raw, err := c.call("get_version_info", nil)
	if err != nil {
		return nil, err
	}
	v := &VersionInfo{}
	if err := decMode.Unmarshal(raw, v); err != nil {
		return nil, fmt.Errorf("jade: decoding version info: %w", err)
	}
	return v, nil
}

// Curve is the only curve Jade's identity functions support.
const Curve = "nist256p1"

// IdentityPubKey returns the 65-byte uncompressed SLIP-0017 (ECDH) public key
// for identity/index. It requires an unlocked device but no confirmation.
func (c *Client) IdentityPubKey(identity string, index uint32) ([]byte, error) {
	raw, err := c.call("get_identity_pubkey", map[string]any{
		"identity": identity,
		"curve":    Curve,
		"index":    index,
		"type":     "slip-0017",
	})
	if err != nil {
		return nil, err
	}
	var pk []byte
	if err := decMode.Unmarshal(raw, &pk); err != nil {
		return nil, fmt.Errorf("jade: decoding pubkey: %w", err)
	}
	if len(pk) != 65 || pk[0] != 4 {
		return nil, fmt.Errorf("jade: unexpected pubkey format (%d bytes)", len(pk))
	}
	return pk, nil
}

// IdentitySharedKey returns the 32-byte ECDH shared secret (the X coordinate
// of d·P) between identity/index and their 65-byte uncompressed public key.
// The user must confirm on the device; this call blocks until they do.
func (c *Client) IdentitySharedKey(identity string, index uint32, theirPubKey []byte) ([]byte, error) {
	raw, err := c.call("get_identity_shared_key", map[string]any{
		"identity":     identity,
		"curve":        Curve,
		"index":        index,
		"their_pubkey": theirPubKey,
	})
	if err != nil {
		return nil, err
	}
	var k []byte
	if err := decMode.Unmarshal(raw, &k); err != nil {
		return nil, fmt.Errorf("jade: decoding shared key: %w", err)
	}
	if len(k) != 32 {
		return nil, fmt.Errorf("jade: unexpected shared key length %d", len(k))
	}
	return k, nil
}

// Logout locks the device, wiping key material from its memory.
func (c *Client) Logout() error {
	_, err := c.call("logout", nil)
	return err
}

func epochNow() int64 { return time.Now().Unix() }
