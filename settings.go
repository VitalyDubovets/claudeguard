package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
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

func hasProxyEnv(m map[string]any, proxyURL string) bool {
	env, _ := m["env"].(map[string]any)
	for _, k := range proxyEnvKeys {
		if env[k] == proxyURL {
			return true
		}
	}
	return false
}

// settingsPrev is ~/.claude/settings.json as it was before claudeguard first
// changed it. It lives next to config.json; uninstall puts the file back.
type settingsPrev struct {
	Existed bool   `json:"existed"`
	Content string `json:"content,omitempty"`
}

func settingsPrevPath() (string, error) { return appSSHFile("settings.prev.json") }

// originalSettings reads the snapshot. Installs made before 0.4.1 have none:
// for them the backup those versions left, or the file itself, stands in.
func originalSettings(path, proxyURL string) settingsPrev {
	if p, err := settingsPrevPath(); err == nil {
		if data, err := os.ReadFile(p); err == nil {
			var prev settingsPrev
			if json.Unmarshal(data, &prev) == nil {
				return prev
			}
		}
	}
	raw, err := os.ReadFile(path + ".claudeguard.bak")
	if err != nil {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return settingsPrev{}
	}
	m := map[string]any{}
	if json.Unmarshal(raw, &m) == nil && hasProxyEnv(m, proxyURL) {
		clearProxyEnv(m, proxyURL)
		if len(m) == 0 {
			// Nothing but our proxy in it: claudeguard made this file.
			return settingsPrev{}
		}
	}
	return settingsPrev{Existed: true, Content: string(raw)}
}

func rememberSettings(path, proxyURL string) error {
	p, err := settingsPrevPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	data, _ := json.Marshal(originalSettings(path, proxyURL))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

// restoreSettings undoes setProxyEnv. If nothing else in the file changed
// since the install, it goes back byte for byte; otherwise only the proxy
// variables do, to the values they had before.
func restoreSettings(path, proxyURL string) error {
	prev := originalSettings(path, proxyURL)
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		_ = os.Remove(path + ".claudeguard.bak")
		return nil
	}
	m, err := readSettings(path)
	if err != nil {
		return err
	}
	orig, installed := map[string]any{}, map[string]any{}
	_ = json.Unmarshal([]byte(prev.Content), &orig)
	_ = json.Unmarshal([]byte(prev.Content), &installed)
	setProxyEnv(installed, proxyURL)
	switch {
	case prev.Existed && !hasProxyEnv(orig, proxyURL) && reflect.DeepEqual(m, installed):
		err = os.WriteFile(path, []byte(prev.Content), 0o600)
	default:
		clearProxyEnv(m, proxyURL)
		old, _ := orig["env"].(map[string]any)
		for _, k := range proxyEnvKeys {
			v, had := old[k]
			if !had || v == proxyURL {
				continue
			}
			env, _ := m["env"].(map[string]any)
			if env == nil {
				env = map[string]any{}
				m["env"] = env
			}
			if _, taken := env[k]; !taken {
				env[k] = v
			}
		}
		if !prev.Existed && len(m) == 0 {
			err = os.Remove(path)
			_ = os.Remove(filepath.Dir(path)) // goes only if it is empty
		} else {
			err = writeSettings(path, m)
		}
	}
	if err == nil {
		_ = os.Remove(path + ".claudeguard.bak")
	}
	return err
}

func configureClaudeCode(proxyURL string, enable bool) error {
	path, err := claudeSettingsPath()
	if err != nil {
		return err
	}
	if !enable {
		return restoreSettings(path, proxyURL)
	}
	m, err := readSettings(path)
	if err != nil {
		return err
	}
	if err := rememberSettings(path, proxyURL); err != nil {
		return err
	}
	setProxyEnv(m, proxyURL)
	return writeSettings(path, m)
}
