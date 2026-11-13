package cli

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/VitalyDubovets/claudeguard/internal/browser"
	"github.com/VitalyDubovets/claudeguard/internal/claudecode"
	"github.com/VitalyDubovets/claudeguard/internal/config"
	"github.com/VitalyDubovets/claudeguard/internal/firewall"
	"github.com/VitalyDubovets/claudeguard/internal/panel"
	"github.com/VitalyDubovets/claudeguard/internal/platform"
	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
	"github.com/VitalyDubovets/claudeguard/internal/tunnel"
	"github.com/VitalyDubovets/claudeguard/internal/version"
)

// installPlan is what one install sets up besides the kill switch and the
// proxy, which always go in.
type installPlan struct {
	launcher bool // "Claude via Proxy" and the settings launcher
	tray     bool // menu bar / tray icon
	settings bool // HTTPS_PROXY in Claude Code's settings.json
	// elevate runs the root half: sudo in a terminal, a system password
	// dialog when started by a double click.
	elevate func(args []string) error
}

// install sets up both halves: the root one (firewall rules and what keeps
// them loaded) and the user's (proxy service, launchers, Claude Code).
func install(cfg config.Config, fw firewall.Options, plan installPlan) error {
	fmt.Println("1/3 Firewall kill switch (needs admin rights)...")
	if err := plan.elevate(append([]string{"system-install"}, fw.Args()...)); err != nil {
		return fmt.Errorf("system part failed: %w", err)
	}
	fmt.Println("2/3 Background proxy, launcher...")
	if err := platform.UserInstall(cfg.ProxyURL(), plan.launcher); err != nil {
		return err
	}
	if plan.tray {
		if err := platform.TrayInstall(); err != nil {
			fmt.Println("   tray icon not installed:", err)
		}
	}
	if plan.settings {
		fmt.Println("3/3 Claude Code settings (env HTTPS_PROXY/HTTP_PROXY)...")
		if err := claudecode.Configure(cfg.ProxyURL(), true); err != nil {
			return fmt.Errorf("~/.claude/settings.json: %w", err)
		}
	}
	return nil
}

func runInstall(args []string) error {
	if sysutil.IsRoot() {
		return errors.New("run install as your normal user; it asks for admin rights itself")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	upstreamURL := fs.String("upstream", "", "add this SOCKS5/HTTP proxy and make it active")
	sshHost := fs.String("ssh", "", "add this SSH host and make it active")
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "local proxy address")
	options := firewallFlags(fs, firewallOptions(cfg))
	noSettings := fs.Bool("no-settings", false, "do not touch ~/.claude/settings.json")
	noLauncher := fs.Bool("no-launcher", false, "do not create the 'Claude via Proxy' launcher")
	noTray := fs.Bool("no-tray", false, "do not add the menu bar / tray icon")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fw, err := options()
	if err != nil {
		return err
	}
	cfg.AllowTunnels, cfg.ExtraBlock = fw.AllowTunnels, fw.Extra
	if p, ok, err := config.ProfileFromFlags(*sshHost, *upstreamURL); err != nil {
		return err
	} else if ok {
		if err := cfg.Upsert(p.Name, p); err != nil {
			return err
		}
		cfg.Active = p.Name
	}
	if err := config.Save(cfg); err != nil {
		return err
	}

	plan := installPlan{launcher: !*noLauncher, tray: !*noTray, settings: !*noSettings, elevate: platform.Elevate}
	if err := install(cfg, fw, plan); err != nil {
		return err
	}
	fmt.Println("\nDone. Restart Claude with the 'Claude via Proxy' launcher (or `claudeguard launch`).")
	if cfg.Active == "" {
		fmt.Println("No server yet: add one in the settings page.")
	}
	fmt.Println("Settings: the 'Claudeguard' launcher or `claudeguard ui`.")
	return nil
}

const (
	askInstall = "Claudeguard пустит Claude через ваш прокси-сервер и закроет прямой доступ к Anthropic: если прокси упадёт, Claude останется без связи, а не пойдёт напрямую.\n\nДля правил файрвола один раз понадобится пароль администратора. Сервер вы выберете на следующем шаге."
	askUpdate  = "Обновить Claudeguard до версии " + version.Version + "?\n\nСерверы и настройки сохранятся. Прокси перезапустится, связь Claude прервётся на несколько секунд. Понадобится пароль администратора."
)

// runApp is what a double click runs: set everything up on the first start
// and after an update, then show the settings window. There is no terminal
// here, so questions and errors are dialogs.
func runApp([]string) error {
	platform.HideConsole()
	if msg := platform.Misplaced(); msg != "" {
		platform.Dialog(platform.DialogInfo, msg)
		return nil
	}
	err := installFromGUI()
	if errors.Is(err, errDeclined) {
		return nil
	}
	if err == nil {
		err = panel.Show()
	}
	if err != nil {
		platform.Dialog(platform.DialogError, "Claudeguard: "+err.Error())
	}
	return err
}

var errDeclined = errors.New("declined")

// installFromGUI installs or updates if this binary is not the one set up,
// asking first. An update keeps the server list and every setting.
func installFromGUI() error {
	cfg, err := config.Load()
	if err != nil || platform.Installed() {
		return err
	}
	kind, text := platform.DialogInstall, askInstall
	update := platform.PreviousInstall()
	if update {
		kind, text = platform.DialogUpdate, askUpdate
	}
	if !platform.Dialog(kind, text) {
		return errDeclined
	}
	if update {
		platform.ClosePanel()
	}
	if err = config.Save(cfg); err == nil {
		plan := installPlan{launcher: true, tray: true, settings: true, elevate: platform.ElevateGUI}
		err = install(cfg, firewallOptions(cfg), plan)
	}
	if err != nil {
		return fmt.Errorf("установка не завершена: %w", err)
	}
	return nil
}

// runUninstall removes the root half first: if the password prompt is
// cancelled, nothing else has been touched and the protection stays whole.
func runUninstall(args []string) error {
	if sysutil.IsRoot() {
		return errors.New("run uninstall as your normal user")
	}
	gui := len(args) == 1 && args[0] == "--gui"
	elevate := platform.Elevate
	if gui {
		platform.HideConsole()
		elevate = platform.ElevateGUI
	}
	cfg, _ := config.Load()
	if err := elevate([]string{"system-uninstall"}); err != nil {
		err = fmt.Errorf("kill switch was not removed, nothing else was touched: %w", err)
		if gui {
			platform.Dialog(platform.DialogError, "Claudeguard не удалён: "+err.Error())
		}
		return err
	}
	notes, err := removeUserHalf(cfg)
	if err == nil {
		text := "Claudeguard удалён, настройки Claude Code возвращены. Перезапустите Claude обычным способом, чтобы он снова ходил напрямую."
		if len(notes) > 0 {
			text += "\n\n" + strings.Join(notes, "\n\n")
		}
		fmt.Println(text)
		if gui {
			platform.Dialog(platform.DialogInfo, text)
		}
	}
	platform.StopProxy()
	return err
}

// removeUserHalf undoes everything install did under the user's account.
// It goes on after a failure; notes are what is left for the user to do.
func removeUserHalf(cfg config.Config) (notes []string, err error) {
	var errs []error
	if left := tunnel.ForgetServerKeys(cfg); len(left) > 0 {
		notes = append(notes, "Ключ Claudeguard остался на сервере "+strings.Join(left, ", ")+
			": сервер не ответил. Строка с пометкой claudeguard в ~/.ssh/authorized_keys удаляется вручную.")
	}
	if err := claudecode.Configure(cfg.ProxyURL(), false); err != nil {
		errs = append(errs, fmt.Errorf("~/.claude/settings.json: %w", err))
	}
	if err := browser.Disable(browser.PACURL(cfg.Listen)); err != nil {
		notes = append(notes, "Настройка прокси для браузеров осталась: "+err.Error()+". Её можно убрать в настройках сети, поле автонастройки прокси.")
	}
	platform.ClosePanel()
	more, err := platform.UserUninstall()
	if err != nil {
		errs = append(errs, err)
	}
	platform.RemoveAppData()
	return append(notes, more...), errors.Join(errs...)
}

func runSystemInstall(args []string) error {
	o, err := parseFirewallArgs("system-install", args)
	if err != nil {
		return err
	}
	if !sysutil.IsRoot() {
		return errors.New("system-install needs admin rights")
	}
	return platform.SystemInstall(o)
}

func runSystemUninstall([]string) error {
	if !sysutil.IsRoot() {
		return errors.New("system-uninstall needs admin rights")
	}
	return platform.SystemUninstall()
}
