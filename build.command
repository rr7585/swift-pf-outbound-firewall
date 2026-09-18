#!/bin/bash
# 双击编译出 PF出站防火墙.app
cd "$(dirname "$0")" || exit 1
echo "==== 跑测试 ===="
if ./test.sh && echo && echo "==== 编译 PF出站防火墙.app ====" && ./build.sh; then
  echo
  echo "✅ 完成，已在 Finder 中定位。双击 PF出站防火墙.app 即可使用。"
  open -R "build/PF出站防火墙.app" 2>/dev/null
else
  echo
  echo "❌ 失败（看上面的报错）"
fi
echo
read -n 1 -s -r -p "按任意键关闭窗口 …"; echo
