//go:build !darwin && !windows

package main

import "errors"

func cmdTray([]string) error { return errors.New("tray: only on macOS and Windows") }
