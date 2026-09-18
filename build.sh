#!/bin/bash
# 把 app/*.swift 编译成 PF出站防火墙.app，不需要 Xcode。
set -euo pipefail
cd "$(dirname "$0")"

APP="build/PF出站防火墙.app"
BIN="PFOutboundFirewall"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

swiftc -O app/Rules.swift app/Core.swift app/Connections.swift app/ContentView.swift app/App.swift -o "$APP/Contents/MacOS/$BIN"

# 图标：没有就现画一个（icon/make-icon.swift 是画法，改完重跑 icon/build-icon.sh）
[ -f icon/AppIcon.icns ] || ./icon/build-icon.sh
cp icon/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>PF出站防火墙</string>
  <key>CFBundleDisplayName</key><string>PF出站防火墙</string>
  <key>CFBundleIdentifier</key><string>com.user.pf-outbound.gui</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>$BIN</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSPrincipalClass</key><string>NSApplication</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST

# Apple Silicon 上未签名的 .app 拷到别的 M 芯片 Mac 会「已损坏」，ad-hoc 签名即可
codesign --force --deep --sign - "$APP" >/dev/null 2>&1

echo "✅ 已生成 $(pwd)/$APP"
