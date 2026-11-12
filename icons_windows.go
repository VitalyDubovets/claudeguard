package main

import _ "embed"

// Drawn by tools/mkicon.
var (
	//go:embed icons/claudeguard.ico
	uiIcon []byte
	//go:embed icons/launcher.ico
	launcherIcon []byte
	//go:embed icons/claudeguard.ico
	trayIcon []byte
	//go:embed icons/tray-off.ico
	trayOffIcon []byte
)
