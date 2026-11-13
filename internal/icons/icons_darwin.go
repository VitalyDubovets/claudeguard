package icons

import (
	_ "embed"
)

// Drawn by tools/mkicon.
var (
	//go:embed img/claudeguard.icns
	UI []byte
	//go:embed img/launcher.icns
	Launcher []byte
	// Template images: macOS tints them for a light or dark menu bar.
	//go:embed img/menubar.png
	Tray []byte
	//go:embed img/menubar-off.png
	TrayOff []byte
	// Dock and window icon of the panel.
	//go:embed img/claudeguard.png
	Window []byte
)
