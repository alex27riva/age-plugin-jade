//go:build !darwin || cgo

package jade

import (
	"fmt"
	"strings"

	"go.bug.st/serial/enumerator"
)

func detect() (string, error) {
	ports, err := enumerator.GetDetailedPortsList()
	if err != nil {
		return "", fmt.Errorf("listing serial ports: %w (set JADE_PORT to select one manually)", err)
	}
	var found []string
	for _, p := range ports {
		if !p.IsUSB {
			continue
		}
		for _, id := range deviceIDs {
			if strings.EqualFold(p.VID, id[0]) && strings.EqualFold(p.PID, id[1]) {
				found = append(found, p.Name)
			}
		}
	}
	return pick(found)
}
