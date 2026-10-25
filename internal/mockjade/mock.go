// Package mockjade is a software stand-in for a Blockstream Jade, for testing
// only. It speaks the device's CBOR-RPC protocol over a net.Conn and derives
// SLIP-0013/0017 nist256p1 identity keys from a BIP-39 seed the same way the
// firmware does (main/identity.c). It provides no security whatsoever.
package mockjade

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// Jade is a mock device.
type Jade struct {
	seed []byte

	mu       sync.Mutex
	unlocked bool
	// Decline makes the "user" reject confirmation prompts.
	Decline bool
	// Network the wallet is locked to: "MAIN" or "TEST".
	Networks string
	// Confirmations counts accepted on-device confirmations.
	Confirmations int
	Logf          func(format string, args ...any)

	pinserver *httptest.Server
}

// TestMnemonic is the standard BIP-39 test vector mnemonic.
const TestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// New creates a locked mock Jade for mnemonic and BIP-39 passphrase.
func New(mnemonic, passphrase string) *Jade {
	seed, err := pbkdf2.Key(sha512.New, mnemonic, []byte("mnemonic"+passphrase), 2048, 64)
	if err != nil {
		panic(err)
	}
	j := &Jade{seed: seed, Networks: "MAIN", Logf: log.Printf}
	// A fake blind PIN server: the device's http_request is relayed by the
	// client to here, and whatever comes back is passed to the "pin" method.
	j.pinserver = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["data"] != "client-ske-blob" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": "server-reply-blob"})
	}))
	return j
}

func (j *Jade) Close() { j.pinserver.Close() }

func (j *Jade) logf(format string, args ...any) {
	if j.Logf != nil {
		j.Logf("mockjade: "+format, args...)
	}
}

// Serve handles connections on l until it is closed.
func (j *Jade) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go j.ServeConn(c)
	}
}

var decMode, _ = cbor.DecOptions{DefaultMapType: reflect.TypeOf(map[string]any(nil))}.DecMode()

type request struct {
	ID     string          `cbor:"id"`
	Method string          `cbor:"method"`
	Params cbor.RawMessage `cbor:"params"`
}

// ServeConn speaks CBOR-RPC on one connection.
func (j *Jade) ServeConn(c io.ReadWriteCloser) {
	defer c.Close()
	dec := decMode.NewDecoder(c)
	enc := cbor.NewEncoder(c)
	// Like debug firmware, emit an unsolicited log message first.
	enc.Encode(map[string]any{"log": []byte("I mock jade ready")})
	for {
		var req request
		if err := dec.Decode(&req); err != nil {
			if err != io.EOF {
				j.logf("decode: %v", err)
			}
			return
		}
		result, code, msg := j.handle(req)
		reply := map[string]any{"id": req.ID}
		if code != 0 {
			reply["error"] = map[string]any{"code": code, "message": msg}
		} else {
			reply["result"] = result
		}
		if err := enc.Encode(reply); err != nil {
			return
		}
	}
}

func (j *Jade) handle(req request) (any, int, string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.logf("<- %s", req.Method)

	var p map[string]any
	if len(req.Params) > 0 {
		if err := decMode.Unmarshal(req.Params, &p); err != nil {
			return nil, -32602, "bad params"
		}
	}

	switch req.Method {
	case "ping":
		return 0, 0, ""
	case "get_version_info":
		state := "LOCKED"
		if j.unlocked {
			state = "READY"
		}
		return map[string]any{"JADE_VERSION": "1.0.99-mock", "JADE_STATE": state,
			"JADE_NETWORKS": j.Networks, "BOARD_TYPE": "MOCK", "JADE_HAS_PIN": true}, 0, ""
	case "auth_user":
		net, _ := p["network"].(string)
		if isTest := strings.Contains(net, "test") || strings.Contains(net, "localtest"); isTest != (j.Networks == "TEST") {
			return nil, -32003, "Network type inconsistent with prior usage"
		}
		if j.unlocked {
			return true, 0, ""
		}
		return map[string]any{"http_request": map[string]any{
			"params": map[string]any{
				"urls":   []any{j.pinserver.URL + "/get_pin", "http://mockonionaddress.onion/get_pin"},
				"method": "POST", "accept": "json",
				"data": map[string]any{"data": "client-ske-blob"},
			},
			"on-reply": "pin",
		}}, 0, ""
	case "pin":
		if p["data"] != "server-reply-blob" {
			return false, 0, ""
		}
		j.unlocked = true
		return true, 0, ""
	case "logout":
		j.unlocked = false
		return true, 0, ""
	case "get_identity_pubkey", "get_identity_shared_key":
		if !j.unlocked {
			return nil, -32002, "Cannot process message - hardware locked or uninitialised"
		}
		identity, _ := p["identity"].(string)
		curve, _ := p["curve"].(string)
		index := uint32(0)
		if v, ok := p["index"].(uint64); ok {
			if v > 0x7fffffff {
				return nil, -32602, "Failed to fetch valid index from parameters"
			}
			index = uint32(v)
		}
		if curve != "nist256p1" {
			return nil, -32602, "Invalid curve"
		}
		if len(identity) >= 192 || !(strings.HasPrefix(identity, "ssh://") || strings.HasPrefix(identity, "gpg://")) {
			return nil, -32602, "Failed to extract valid identity from parameters"
		}
		if req.Method == "get_identity_pubkey" {
			typ, _ := p["type"].(string)
			prefix := uint32(0)
			switch typ {
			case "slip-0013":
				prefix = 13
			case "slip-0017":
				prefix = 17
			default:
				return nil, -32602, "Invalid key type"
			}
			return j.key(prefix, identity, index).PublicKey().Bytes(), 0, ""
		}
		their, _ := p["their_pubkey"].([]byte)
		pub, err := ecdh.P256().NewPublicKey(their)
		if err != nil {
			return nil, -32602, "Failed to extract valid pubkey from parameters"
		}
		if j.Decline {
			j.logf("user declined %q", identity)
			return nil, -32000, "User declined to share identity key"
		}
		j.Confirmations++
		j.logf("user confirmed %q", identity)
		s, err := j.key(17, identity, index).ECDH(pub)
		if err != nil {
			return nil, -32603, err.Error()
		}
		return s, 0, ""
	default:
		return nil, -32601, fmt.Sprintf("Unknown method '%s'", req.Method)
	}
}

var p256N = func() *big.Int {
	n, _ := new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
	return n
}()

// key derives the identity key like the firmware: SLIP-0010 nist256p1 master
// key from the seed, then hardened path m/prefix'/h0'/h1'/h2'/h3' where hN are
// little-endian uint32 words of SHA-256(LE32(index) || identity).
func (j *Jade) key(prefix uint32, identity string, index uint32) *ecdh.PrivateKey {
	h := sha256.New()
	binary.Write(h, binary.LittleEndian, index)
	h.Write([]byte(identity))
	ih := h.Sum(nil)
	path := []uint32{0x80000000 | prefix}
	for i := 0; i < 4; i++ {
		path = append(path, 0x80000000|binary.LittleEndian.Uint32(ih[4*i:]))
	}

	m := hmac.New(sha512.New, []byte("Nist256p1 seed"))
	m.Write(j.seed)
	I := m.Sum(nil)
	k, c := new(big.Int).SetBytes(I[:32]), I[32:]
	for _, idx := range path {
		var data [37]byte
		k.FillBytes(data[1:33])
		binary.BigEndian.PutUint32(data[33:], idx)
		m := hmac.New(sha512.New, c)
		m.Write(data[:])
		I := m.Sum(nil)
		k.Add(k, new(big.Int).SetBytes(I[:32]))
		k.Mod(k, p256N)
		c = I[32:]
	}
	var kb [32]byte
	k.FillBytes(kb[:])
	priv, err := ecdh.P256().NewPrivateKey(kb[:])
	if err != nil {
		panic(err)
	}
	return priv
}
