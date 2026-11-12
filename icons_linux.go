package main

import _ "embed"

// Drawn by tools/mkicon.
var (
	//go:embed icons/claudeguard.png
	uiIcon []byte
	//go:embed icons/launcher.png
	launcherIcon []byte
	//go:embed icons/tray.png
	trayIcon []byte
	//go:embed icons/tray-off.png
	trayOffIcon []byte
)
