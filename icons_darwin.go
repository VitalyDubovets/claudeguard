package main

import _ "embed"

// Drawn by tools/mkicon.
var (
	//go:embed icons/claudeguard.icns
	uiIcon []byte
	//go:embed icons/launcher.icns
	launcherIcon []byte
	// Template images: macOS tints them for a light or dark menu bar.
	//go:embed icons/menubar.png
	trayIcon []byte
	//go:embed icons/menubar-off.png
	trayOffIcon []byte
)
