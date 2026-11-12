#!/bin/sh
# Removing the package takes the kill switch and its systemd units with it.
# deb passes "upgrade" and rpm passes 1 when the package is only being
# updated: then everything stays.
case "$1" in
upgrade | 1 | 2) exit 0 ;;
esac
/usr/bin/claudeguard system-uninstall >/dev/null 2>&1 || true
