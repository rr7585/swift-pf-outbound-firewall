#!/bin/bash
# 由 icon/make-icon.swift 生成 icon/AppIcon.icns。
# 改了画法就重跑这个脚本，然后再跑 ../build.sh。
set -euo pipefail
cd "$(dirname "$0")"

SET=AppIcon.iconset
rm -rf "$SET"; mkdir -p "$SET"

swiftc -O -parse-as-library make-icon.swift -o /tmp/pf-make-icon.$$
/tmp/pf-make-icon.$$ "$SET"
rm -f /tmp/pf-make-icon.$$

iconutil -c icns "$SET" -o AppIcon.icns
rm -rf "$SET"
echo "✅ 已生成 $(pwd)/AppIcon.icns ($(du -h AppIcon.icns | cut -f1))"
