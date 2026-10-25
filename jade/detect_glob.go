//go:build darwin && !cgo

package jade

import "path/filepath"

// Without cgo, macOS USB enumeration is unavailable: fall back to the device
// node names used by the USB-serial chips Jade units ship with.
func detect() (string, error) {
	var found []string
	for _, pat := range []string{"/dev/cu.SLAB_USBtoUART*", "/dev/cu.usbserial*",
		"/dev/cu.wchusbserial*", "/dev/cu.usbmodem*"} {
		m, _ := filepath.Glob(pat)
		found = append(found, m...)
	}
	return pick(found)
}
