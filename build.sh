#!/bin/bash
# Builds everything that goes into a release, on a Mac:
#   dist/Claudeguard-VERSION.dmg              macOS app, Apple silicon and Intel
#   dist/ClaudeguardSetup-VERSION-ARCH.exe    Windows installer
#   dist/claudeguard_VERSION_ARCH.deb, .rpm, .pkg.tar.zst, .tar.gz   Linux
# Set SIGN_ID to a "Developer ID Application: ..." identity to sign the
# macOS app for real; without it the app gets an ad-hoc signature.
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(sed -n 's/^const Version = "\(.*\)"/\1/p' internal/version/version.go)
[ -n "$VERSION" ] || { echo "no version in internal/version/version.go" >&2; exit 1; }
MAIN=./cmd/claudeguard
ICONS=internal/icons/img
FLAGS=(-trimpath -ldflags "-s -w")
rm -rf dist && mkdir -p dist

echo "== macOS"
for arch in arm64 amd64; do
	CGO_ENABLED=1 GOOS=darwin GOARCH=$arch go build "${FLAGS[@]}" -o dist/claudeguard-darwin-$arch $MAIN
done
app=dist/stage/Claudeguard.app
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
lipo -create -output "$app/Contents/MacOS/claudeguard" dist/claudeguard-darwin-arm64 dist/claudeguard-darwin-amd64
cp $ICONS/claudeguard.icns "$app/Contents/Resources/"
sed "s/@VERSION@/$VERSION/g" packaging/Info.plist >"$app/Contents/Info.plist"
codesign --force --sign "${SIGN_ID:--}" ${SIGN_ID:+--options runtime --timestamp} "$app"
ln -s /Applications dist/stage/Applications
hdiutil create -quiet -volname Claudeguard -srcfolder dist/stage -ov -format UDZO "dist/Claudeguard-$VERSION.dmg"
rm -rf dist/stage

echo "== Windows"
for arch in amd64 arm64; do
	go run github.com/akavel/rsrc@v0.10.2 -ico $ICONS/claudeguard.ico -arch $arch -o $MAIN/rsrc_windows_$arch.syso
	CGO_ENABLED=0 GOOS=windows GOARCH=$arch go build "${FLAGS[@]}" -o "dist/ClaudeguardSetup-$VERSION-$arch.exe" $MAIN
	rm -f $MAIN/rsrc_windows_$arch.syso
done

echo "== Linux"
for arch in amd64 arm64; do
	CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build "${FLAGS[@]}" -o dist/claudeguard-linux-$arch $MAIN
	sed "s/@ARCH@/$arch/g; s/@VERSION@/$VERSION/g" packaging/nfpm.yaml >dist/nfpm.yaml
	for fmt in deb rpm archlinux; do
		go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.41.1 pkg --config dist/nfpm.yaml --packager $fmt --target dist/
	done
	# For SteamOS and anything else: unpack and run ./claudeguard install.
	mkdir -p dist/t && cp dist/claudeguard-linux-$arch dist/t/claudeguard
	COPYFILE_DISABLE=1 tar --no-xattrs -czf "dist/claudeguard_${VERSION}_linux_$arch.tar.gz" -C dist/t claudeguard
	rm -rf dist/t
	rm dist/nfpm.yaml
done
ls -lh dist
