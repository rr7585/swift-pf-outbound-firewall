#!/bin/bash
# 拿真正的 pfctl 核对 isValidAllowlistEntry 的判断。
#
# 单元测试只能证明校验器自洽，证明不了它和 pf 想的一样。这个脚本把每条样本
# 真的塞进 pf 表里让 pfctl 解析一遍，比对两边结论。
#
# pfctl -nf 只解析不加载，不需要 root，也不会碰当前生效的规则。
#
# 判定标准是单向的：**校验器接受的，pf 必须也接受**。
# 反过来允许 —— 我们有意比 pf 严的地方见下面 KNOWN_STRICTER。
set -uo pipefail
cd "$(dirname "$0")/.."

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# 有意比 pf 严的条目，出现分歧不算失败
KNOWN_STRICTER=(
    "01.2.3.4"      # 前导零：pf 按十进制收，但别的工具会按八进制读
    "010.1.1.1"
    "example.com"   # 域名：pf 在加载时解析一次，而开机加载时 DNS 正被挡着
    # pf 走宽松的 inet_aton，认 IPv4 简写，而且含义常与直觉相反：
    #   1.2.3 → 1.2.0.3      1.2 → 1.0.0.2      16909060 → 1.2.3.4
    # 我们走严格的 inet_pton，只认四段点分写法。
    "1.2.3"
    "1.2"
    "16909060"
)

SAMPLES=(
    8.8.8.8 0.0.0.0 255.255.255.255 192.168.1.0/24 10.0.0.0/8 1.2.3.4/32 1.2.3.4/0
    2001:4860:4860::8888 2606:4700::/32 ::1 :: fe80::1 fe80::1%en0
    ::ffff:192.168.1.1 2001:db8:85a3:0:0:8a2e:370:7334 2001:db8::/128 2001:db8::/0
    256.1.1.1 1.2.3 1.2 16909060 1.2.3.4.5 1.2.3.4/33 01.2.3.4 010.1.1.1 example.com
    2001:xyz::1 2001:db8:::1 2001:db8::1/129 12345::1 -1.2.3.4
)

cat > "$WORK/verdict.swift" <<'SWIFT'
import Foundation
@main enum Verdict {
    static func main() {
        while let line = readLine(strippingNewline: true) {
            print(isValidAllowlistEntry(line) ? "accept" : "reject")
        }
    }
}
SWIFT
swiftc -O app/Rules.swift "$WORK/verdict.swift" -o "$WORK/verdict" || exit 1

cat > "$WORK/rules.conf" <<EOF
table <vpn_allowlist> persist file "$WORK/one.txt"
pass out quick on lo0 all
pass out quick on utun* all
pass out quick to <vpn_allowlist>
block drop out quick all
EOF

printf '%s\n' "${SAMPLES[@]}" | "$WORK/verdict" > "$WORK/verdicts.txt"

failures=0
stricter=0
index=0
while read -r ours; do
    entry="${SAMPLES[$index]}"
    index=$((index + 1))

    printf '%s\n' "$entry" > "$WORK/one.txt"
    if /sbin/pfctl -nf "$WORK/rules.conf" >/dev/null 2>&1; then pf=accept; else pf=reject; fi
    [ "$ours" = "$pf" ] && continue

    known=no
    for allowed in "${KNOWN_STRICTER[@]}"; do
        [ "$entry" = "$allowed" ] && known=yes && break
    done

    if [ "$ours" = "accept" ]; then
        # 这个方向永远是错的：我们放过了 pf 会拒的东西
        echo "❌ $entry —— 校验器接受，pf 拒绝"
        failures=$((failures + 1))
    elif [ "$known" = yes ]; then
        stricter=$((stricter + 1))
    else
        echo "❌ $entry —— 校验器拒绝，但 pf 接受，且不在 KNOWN_STRICTER 里"
        failures=$((failures + 1))
    fi
done < "$WORK/verdicts.txt"

echo "已比对 ${#SAMPLES[@]} 条，其中 $stricter 条是有意从严"
if [ "$failures" -gt 0 ]; then
    echo "❌ $failures 条与 pf 不符"
    exit 1
fi
echo "✅ 与 pf 判断一致"
