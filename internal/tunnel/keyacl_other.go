//go:build !windows

package tunnel

// protectKey has nothing to do here: the key is written with mode 0600.
func protectKey(string) error { return nil }
