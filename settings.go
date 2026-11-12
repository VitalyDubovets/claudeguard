package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// Claude Code (CLI and the agent inside the desktop app) reads the "env"
// block of ~/.claude/settings.json, so the proxy applies however it starts.
var proxyEnvKeys = []string{"HTTPS_PROXY", "HTTP_PROXY"}

func claudeSettingsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "settings.json"), nil
}

func readSettings(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]any{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func writeSettings(path string, m map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(path + ".claudeguard.bak"); errors.Is(err, fs.ErrNotExist) {
		if orig, err := os.ReadFile(path); err == nil {
			_ = os.WriteFile(path+".claudeguard.bak", orig, 0o600)
		}
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func setProxyEnv(m map[string]any, proxyURL string) {
	env, _ := m["env"].(map[string]any)
	if env == nil {
		env = map[string]any{}
	}
	for _, k := range proxyEnvKeys {
		env[k] = proxyURL
	}
	m["env"] = env
}

// clearProxyEnv only removes values that claudeguard itself set.
func clearProxyEnv(m map[string]any, proxyURL string) {
	env, _ := m["env"].(map[string]any)
	if env == nil {
		return
	}
	for _, k := range proxyEnvKeys {
		if env[k] == proxyURL {
			delete(env, k)
		}
	}
	if len(env) == 0 {
		delete(m, "env")
	}
}

func configureClaudeCode(proxyURL string, enable bool) error {
	path, err := claudeSettingsPath()
	if err != nil {
		return err
	}
	m, err := readSettings(path)
	if err != nil {
		return err
	}
	if enable {
		setProxyEnv(m, proxyURL)
	} else {
		clearProxyEnv(m, proxyURL)
	}
	return writeSettings(path, m)
}
