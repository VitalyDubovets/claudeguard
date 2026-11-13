package config

import (
	"os"
	"path/filepath"
)

// Setting up a new server happens in-process with x/crypto/ssh: it is the
// only step that needs a password, and that password never touches disk or
// the system ssh. The tunnel itself keeps running on the system ssh, with
// the key and known_hosts that claudeguard owns (next to config.json).

// File returns the path of a file kept next to config.json.
func File(name string) (string, error) {
	cfg, err := Path()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfg), name), nil
}

// Path is where config.json lives; CLAUDEGUARD_CONFIG overrides it.
func Path() (string, error) {
	if p := os.Getenv("CLAUDEGUARD_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "claudeguard", "config.json"), nil
}
