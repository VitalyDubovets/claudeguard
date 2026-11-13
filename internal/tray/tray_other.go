//go:build !darwin && !windows && !linux

package tray

import (
	"errors"
)

func Run([]string) error { return errors.New("tray: not supported on this OS") }
