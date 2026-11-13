package icons

import (
	_ "embed"
)

// Drawn by tools/mkicon.
var (
	//go:embed img/claudeguard.png
	UI []byte
	//go:embed img/launcher.png
	Launcher []byte
	//go:embed img/tray.png
	Tray []byte
	//go:embed img/tray-off.png
	TrayOff []byte
)
