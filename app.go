package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

// sameFile reports whether two files have the same contents.
func sameFile(a, b string) bool {
	sum := func(p string) []byte {
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return nil
		}
		return h.Sum(nil)
	}
	x, y := sum(a), sum(b)
	return x != nil && bytes.Equal(x, y)
}

type installOptions struct {
	launcher, tray, settings bool
}

// doInstall sets up both halves. elev runs the root half: sudo in a
// terminal, a system password dialog when started by a double click.
func doInstall(cfg Config, fw FirewallOptions, o installOptions, elev func([]string) error) error {
	fmt.Println("1/3 Firewall kill switch (needs admin rights)...")
	if err := elev(append([]string{"system-install"}, fw.args()...)); err != nil {
		return fmt.Errorf("system part failed: %w", err)
	}
	fmt.Println("2/3 Background proxy, launcher...")
	if err := userInstall(cfg, o.launcher); err != nil {
		return err
	}
	if o.tray {
		if err := trayInstall(); err != nil {
			fmt.Println("   tray icon not installed:", err)
		}
	}
	if o.settings {
		fmt.Println("3/3 Claude Code settings (env HTTPS_PROXY/HTTP_PROXY)...")
		if err := configureClaudeCode(cfg.proxyURL(), true); err != nil {
			return fmt.Errorf("~/.claude/settings.json: %w", err)
		}
	}
	return nil
}

// cmdApp is what a double click runs: set everything up on the first start
// and after an update, then show the settings window. There is no terminal
// here, so questions and errors are dialogs.
func cmdApp() error {
	hideConsole()
	if msg := misplaced(); msg != "" {
		dialog("info", msg)
		return nil
	}
	cfg, err := loadConfig()
	if err == nil && !installed() {
		// An older version is in place: this start replaces it and keeps
		// the server list and every setting.
		update := previousInstall()
		ask := "Claudeguard пустит Claude через ваш прокси-сервер и закроет прямой доступ к Anthropic: если прокси упадёт, Claude останется без связи, а не пойдёт напрямую.\n\nДля правил файрвола один раз понадобится пароль администратора. Сервер вы выберете на следующем шаге."
		if update {
			ask = "Обновить Claudeguard до версии " + version + "?\n\nСерверы и настройки сохранятся. Прокси перезапустится, связь Claude прервётся на несколько секунд. Понадобится пароль администратора."
		}
		if !dialog(map[bool]string{false: "ask", true: "update"}[update], ask) {
			return nil
		}
		if update {
			closePanel()
		}
		if err = saveConfig(cfg); err == nil {
			err = doInstall(cfg, cfg.firewall(), installOptions{launcher: true, tray: true, settings: true}, elevateGUI)
		}
		if err != nil {
			err = fmt.Errorf("установка не завершена: %w", err)
		}
	}
	if err == nil {
		err = cmdWindow()
	}
	if err != nil {
		dialog("error", "Claudeguard: "+err.Error())
	}
	return err
}
