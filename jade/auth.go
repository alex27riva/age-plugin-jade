package jade

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ErrWrongPIN is returned by Auth when the PIN entered on the device was wrong.
var ErrWrongPIN = errors.New("jade: incorrect PIN")

// HTTPClient is used to relay the blind PIN server exchange. It honours
// HTTPS_PROXY and friends.
var HTTPClient = &http.Client{Timeout: 60 * time.Second}

type httpRequest struct {
	Params struct {
		URLs   []string `cbor:"urls"`
		Method string   `cbor:"method"`
		Accept string   `cbor:"accept"`
		Data   any      `cbor:"data"`
	} `cbor:"params"`
	OnReply string `cbor:"on-reply"`
}

// Auth unlocks the device for network ("mainnet" or "testnet"). If it is
// already unlocked it returns immediately; otherwise the user enters their
// PIN on the device and Auth relays the exchange with the blind PIN server.
func (c *Client) Auth(network string) error {
	method := "auth_user"
	var params any = map[string]any{"network": network, "epoch": epochNow()}

	for range 8 { // the real flow needs 1-2 round trips
		raw, err := c.call(method, params)
		if err != nil {
			return err
		}

		var done bool
		if err := decMode.Unmarshal(raw, &done); err == nil {
			if !done {
				return ErrWrongPIN
			}
			return nil
		}

		var wrapper struct {
			HTTPRequest *httpRequest `cbor:"http_request"`
		}
		if err := decMode.Unmarshal(raw, &wrapper); err != nil || wrapper.HTTPRequest == nil {
			return fmt.Errorf("jade: unexpected %s reply: %s", method, diag(raw))
		}
		body, err := doHTTP(wrapper.HTTPRequest)
		if err != nil {
			return fmt.Errorf("jade: PIN server: %w", err)
		}
		method, params = wrapper.HTTPRequest.OnReply, body
	}
	return errors.New("jade: too many PIN server round trips")
}

func doHTTP(r *httpRequest) (any, error) {
	var url string
	for _, u := range r.Params.URLs {
		if u != "" && !strings.Contains(u, ".onion") {
			url = u
			break
		}
	}
	if url == "" {
		return nil, fmt.Errorf("no usable (non-onion) URL in %v", r.Params.URLs)
	}
	if r.Params.Method != "POST" && r.Params.Method != "GET" {
		return nil, fmt.Errorf("unsupported method %q", r.Params.Method)
	}
	useJSON := r.Params.Accept == "json" || r.Params.Accept == "application/json"

	var reqBody io.Reader
	if r.Params.Method == "POST" {
		var b []byte
		if s, ok := r.Params.Data.(string); ok && !useJSON {
			b = []byte(s)
		} else {
			var err error
			if b, err = json.Marshal(r.Params.Data); err != nil {
				return nil, fmt.Errorf("encoding request: %w", err)
			}
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequest(r.Params.Method, url, reqBody)
	if err != nil {
		return nil, err
	}
	if reqBody != nil && useJSON {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", url, resp.Status)
	}
	if !useJSON {
		return string(data), nil
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return v, nil
}

func diag(raw cbor.RawMessage) string {
	s, err := cbor.Diagnose(raw)
	if err != nil || len(s) > 200 {
		return fmt.Sprintf("%d bytes", len(raw))
	}
	return s
}
