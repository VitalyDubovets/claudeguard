//go:build !darwin && !windows && !linux

package main

import "errors"

func cmdTray([]string) error { return errors.New("tray: not supported on this OS") }
