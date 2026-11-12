//go:build darwin || windows || linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"fyne.io/systray"
)

// cmdTray puts claudeguard into the menu bar (macOS) or the notification
// area (Windows, Linux desktops with a StatusNotifier tray). It is a separate process and only a client of the settings
// API: the proxy keeps working whether the icon is there or not.
func cmdTray(args []string) error {
	if len(args) == 1 && args[0] == "--detach" {
		return detachServe([]string{"tray"})
	}
	if len(args) > 0 {
		return errors.New("usage: claudeguard tray [--detach]")
	}
	systray.Run(func() { go trayLoop() }, func() {})
	return nil
}

// trayView is what the menu shows; it is rebuilt only when this changes.
type trayView struct {
	Running  bool
	Active   string
	State    string
	Servers  []string
	Firewall string
}

func (v trayView) online() bool {
	return v.Running && v.Active != "" && (v.State == "up" || v.State == "direct")
}

func (v trayView) status() string {
	switch {
	case !v.Running:
		return "Прокси не запущен"
	case v.Active == "":
		return "Сервер не выбран, Claude офлайн"
	case v.online():
		return "Claude идёт через " + v.Active
	case v.State == "starting":
		return "Подключаюсь к " + v.Active + "…"
	}
	return v.Active + " не отвечает, Claude офлайн"
}

func (v trayView) killSwitch() string {
	switch {
	case v.Firewall == "":
		return "Kill switch: проверяю…"
	case strings.HasPrefix(v.Firewall, "installed"), v.Firewall == "active":
		return "Kill switch включён"
	}
	return "Kill switch не установлен"
}

func trayAPI(cfg Config, path string, body, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	method, rd := http.MethodGet, &bytes.Buffer{}
	if body != nil {
		method = http.MethodPost
		json.NewEncoder(rd).Encode(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+cfg.Listen+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("X-Claudeguard-Token", cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	// Never through a proxy: this is our own port on this machine.
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error string }
		json.NewDecoder(resp.Body).Decode(&e)
		return errors.New(e.Error)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func trayRead(firewall string) trayView {
	v := trayView{Firewall: firewall}
	cfg, err := loadConfig()
	if err != nil {
		return v
	}
	// The token goes only to a listener that proved it is our claudeguard.
	if !strings.HasPrefix(proxyIdentity(cfg), "running") {
		return v
	}
	var st stateView
	if trayAPI(cfg, "/api/state", nil, &st) != nil {
		return v
	}
	v.Running, v.Active, v.State = true, st.Active, st.Tunnel.State
	for _, p := range st.Profiles {
		v.Servers = append(v.Servers, p.Name)
	}
	return v
}

func trayLoop() {
	var (
		shown    string
		firewall string
		checked  time.Time
		stop     = func() {}
	)
	refresh := make(chan struct{}, 1)
	for {
		// The firewall check runs a system tool; once a minute is plenty.
		if time.Since(checked) > time.Minute {
			firewall, checked = firewallStatus(), time.Now()
		}
		v := trayRead(firewall)
		if key, _ := json.Marshal(v); string(key) != shown {
			shown = string(key)
			stop()
			stop = trayMenu(v, refresh)
		}
		select {
		case <-refresh:
		case <-time.After(3 * time.Second):
		}
	}
}

// trayMenu redraws the icon and the whole menu and returns a func that
// retires this menu's click handlers.
func trayMenu(v trayView, refresh chan<- struct{}) (stop func()) {
	if v.online() {
		systray.SetTemplateIcon(trayIcon, trayIcon)
	} else {
		systray.SetTemplateIcon(trayOffIcon, trayOffIcon)
	}
	systray.SetTooltip("Claudeguard: " + v.status())
	systray.ResetMenu()
	done := make(chan struct{})
	on := func(item *systray.MenuItem, f func()) {
		go func() {
			for {
				select {
				case <-item.ClickedCh:
					f()
					select {
					case refresh <- struct{}{}:
					default:
					}
				case <-done:
					return
				}
			}
		}()
	}
	call := func(path string, body any) {
		if cfg, err := loadConfig(); err == nil && strings.HasPrefix(proxyIdentity(cfg), "running") {
			_ = trayAPI(cfg, path, body, nil)
		}
	}

	systray.AddMenuItem(v.status(), "").Disable()
	systray.AddMenuItem(v.killSwitch(), "").Disable()
	if v.Running {
		systray.AddSeparator()
		for _, name := range v.Servers {
			item := systray.AddMenuItemCheckbox(name, "Пустить Claude через "+name, name == v.Active)
			on(item, func() { call("/api/activate", map[string]string{"name": name}) })
		}
		if len(v.Servers) == 0 {
			systray.AddMenuItem("Серверов пока нет", "").Disable()
		}
	}
	systray.AddSeparator()
	on(systray.AddMenuItem("Открыть Claudeguard…", "Панель настроек"), func() { _ = cmdUI(nil) })
	if v.Running {
		on(systray.AddMenuItem("Перезапустить Claude через прокси", ""), func() { call("/api/launch", struct{}{}) })
	}
	systray.AddSeparator()
	on(systray.AddMenuItem("Убрать значок", "Прокси и kill switch продолжат работать"), systray.Quit)
	return func() { close(done) }
}
