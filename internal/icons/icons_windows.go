package icons

import (
	_ "embed"
)

// Drawn by tools/mkicon.
var (
	//go:embed img/claudeguard.ico
	UI []byte
	//go:embed img/launcher.ico
	Launcher []byte
	//go:embed img/claudeguard.ico
	Tray []byte
	//go:embed img/tray-off.ico
	TrayOff []byte
)
