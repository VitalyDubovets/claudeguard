//go:build !darwin && !windows && !linux

package firewall

import "github.com/VitalyDubovets/claudeguard/internal/sysutil"

func Enable(Options) error { return sysutil.ErrUnsupported }

func Disable() error { return sysutil.ErrUnsupported }

func Status() string { return "unsupported OS" }
