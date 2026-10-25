package jade

import (
	"errors"
	"fmt"
)

func pick(found []string) (string, error) {
	switch len(found) {
	case 0:
		return "", errors.New("no Jade found: is it plugged in and unlocked to the main screen? (set JADE_PORT to select a port manually)")
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("multiple possible Jades found %v: set JADE_PORT to pick one", found)
	}
}
