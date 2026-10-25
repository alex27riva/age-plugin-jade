// Package jade is a minimal client for the Blockstream Jade CBOR-RPC API,
// covering only what age-plugin-jade needs: unlocking the device (auth_user,
// relaying the blind PIN server exchange) and the SLIP-0013/0017 identity calls.
//
// API reference: https://blockstreamjade.readthedocs.io/
package jade

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"go.bug.st/serial"
)

// Known USB VID/PID pairs of Jade units and compatible DIY boards.
// Kept in sync with jadepy's JadeSerialImpl.JADE_DEVICE_IDS.
var deviceIDs = [][2]string{
	{"10C4", "EA60"}, // CP210x (original Jade)
	{"1A86", "55D4"}, // CH9102 (Jade v1.1)
	{"0403", "6001"}, // FTDI
	{"1A86", "7523"}, // CH340
	{"303A", "4001"}, // ESP32-S3 native USB (Jade Plus)
	{"303A", "1001"}, // ESP32-S3 USB-Serial/JTAG
}

const baudRate = 115200

// Open connects to a Jade.
//
// port may be:
//   - "" to auto-detect (honouring the JADE_PORT environment variable),
//   - a serial device such as /dev/ttyACM0 or COM3,
//   - "tcp:host:port" for the Jade QEMU emulator or a test double.
func Open(port string) (*Client, error) {
	if port == "" {
		port = os.Getenv("JADE_PORT")
	}
	if port == "" {
		p, err := detect()
		if err != nil {
			return nil, err
		}
		port = p
	}

	var rw io.ReadWriteCloser
	if addr, ok := strings.CutPrefix(port, "tcp:"); ok {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("connecting to %s: %w", port, err)
		}
		rw = c
	} else {
		sp, err := serial.Open(port, &serial.Mode{BaudRate: baudRate})
		if err != nil {
			return nil, fmt.Errorf("opening %s: %w", port, err)
		}
		// Asserting RTS/DTR can reset ESP32-based hardware: keep both low,
		// as jadepy does.
		_ = sp.SetRTS(false)
		_ = sp.SetDTR(false)
		rw = &serialPort{sp}
	}
	return newClient(rw), nil
}

// serialPort keeps RTS/DTR low on close too.
type serialPort struct{ serial.Port }

func (s *serialPort) Close() error {
	_ = s.SetRTS(false)
	_ = s.SetDTR(false)
	return s.Port.Close()
}
