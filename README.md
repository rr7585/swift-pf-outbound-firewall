# PF Outbound Firewall

macOS 出站防火墙 / VPN 防 IP 泄漏开关（Kill-Switch），基于系统自带的 **PF**。
Swift 重写版，前身是 `legacy/PFOutboundFirewall.applescript`。

防护开启后默认阻断所有出站流量，只放行：

- `lo0` 本地回环
- `utun0` ~ `utun9` 虚拟网卡（VPN / 代理加密后的流量）
- 白名单里的目的 IP / CIDR（VPN 节点、局域网、必需的直连地址）

VPN 断线或分流失效时，流量不会 fallback 到物理网卡，真实 IP 不泄漏。

## 编译

不需要 Xcode，`swiftc` 直接编译：

```bash
./build.command        # 双击也行：跑测试 + 编译 + 在 Finder 里定位
```

或者分开来：

```bash
./test.sh              # 只跑测试
./build.sh             # 只编译 → build/PF出站防火墙.app
```

要求 macOS 13+。产物会做 ad-hoc 签名（Apple Silicon 上不签名的 .app
拷到别的机器会报「已损坏」）。

## 目录结构

| 路径 | 说明 |
| --- | --- |
| `app/Rules.swift` | 路径常量、PF 规则文本、白名单校验、root 侧脚本。纯函数，不执行任何东西 |
| `app/Core.swift` | 提权执行与状态查询 |
| `app/App.swift` | SwiftUI 界面 |
| `tests/RulesTests.swift` | `Rules.swift` 的测试，不依赖 XCTest / Xcode |
| `legacy/PFOutboundFirewall.applescript` | AppleScriptObjC 原版，行为参照 |
| `legacy/pf-rules-standalone.sh` | 纯 shell 版，白名单写死在脚本里，`sudo` 跑一次当次生效 |

`Rules.swift` 只 import Foundation，所以 `test.sh` 能把它和测试文件一起编译成
一个可执行文件跑掉 —— 不用装 App，也不用 root。

## 界面

- **安装并启用 / 保存并生效** — 写白名单、校验并加载 PF 规则
- **启用防护 / 关闭防护** — 临时开关，不删配置
- **卸载** — 停用 PF、移除开机自启、删除全部配置

白名单每行一个 IPv4 或 IPv4/CIDR，`#` 开头是注释。保存前逐行校验，
有错会直接把光标定位到出错那行并选中。

## 安装后落地的文件

| 路径 | 说明 |
| --- | --- |
| `/Library/Application Support/PFOutboundFirewall/allowlist.txt` | 白名单 |
| `/Library/Application Support/PFOutboundFirewall/rules.conf` | 生成的 PF 规则 |
| `/Library/Application Support/PFOutboundFirewall/startup.sh` | 开机加载脚本 |
| `/Library/Application Support/PFOutboundFirewall/startup.log` | 开机加载日志 |
| `/Library/LaunchDaemons/com.user.pf-outbound.plist` | LaunchDaemon（`RunAtLoad`） |
| `/var/run/com.user.pf-outbound.disabled` | 关闭标记，重启后自动清空并恢复防护 |

安装、保存、开关防护都需要管理员密码。

## 实现上几个要记住的点

**提权**。`Core.swift` 的 `runAdmin` 把脚本写进当前用户专属的临时目录
（`/var/folders/…`，0700），再用 `osascript` 的 `do shell script … with
administrator privileges` 执行它。脚本路径通过 argv 传给 osascript，不拼进
AppleScript 字面量，所以只剩 shell 一层引用要管，由 `shellQuote` 负责 ——
白名单是用户输入，最终会落到 root 执行的脚本里，测试里专门有注入用例。

**先校验再覆盖**。保存白名单时先写临时文件、用 `pfctl -nf` 干跑一遍，
通过了才 `mv` 覆盖正式文件。跳过这步的话，一条笔误的规则就能把自己锁死。

**`block` 必须是最后一条**。pf 的 `quick` 先匹配先生效，兜底的
`block drop out quick all` 跑到前面去就等于全断网。测试里锁了这条。

**`pfctl -f` 要重试**。macOS 偶尔有别的系统服务占着 PF 事务锁，
直接加载会报 `DIOCXCOMMIT: Resource busy`，重试十次基本都能过。

**安装时不要并发加载 PF**。`launchctl bootstrap` 的 `RunAtLoad` 已经会加载一次，
安装脚本再来一次就会撞锁。所以安装脚本改成轮询 `installed.ok`
（开机脚本最后一步才 touch），最多等 10 秒。

**关闭标记放 `/var/run`**。重启后自动清空，开机任务重新开启防护 ——
kill-switch 不应该因为你昨天临时关过就一直关着。

**窗口尺寸别用 `.windowResizability(.contentMinSize)`**。它把窗口最小尺寸钉在
内容最小尺寸上，而 `AllowlistEditor` 包着的 NSScrollView 会报一个很大的固有尺寸，
最小宽度会变成 900pt，小屏上缩不小。更隐蔽的是「未安装」状态下编辑器压根没显示，
`if/else` 的另一个分支照样参与这个计算。

## 排障

```bash
sudo pfctl -s info                      # PF 是否 Enabled
sudo pfctl -s rules                     # 当前规则
sudo pfctl -t vpn_allowlist -T show     # 白名单表
cat /Library/Application\ Support/PFOutboundFirewall/startup.log
```

被锁死且界面也打不开时：

```bash
sudo pfctl -d                                        # 临时关闭 PF
sudo launchctl bootout system/com.user.pf-outbound   # 停掉开机自启
```

## 与 AppleScript 原版的差异

- 启用防护从两次提权合成一次（原版 `saveAllowlist` + `enable` 各弹一次密码）
- 原版手搓了一整套 `configureMainMenu` 才让 ⌘C/⌘V 能用，SwiftUI 自带标准编辑菜单，全删了
- 原版为了能在脚本编辑器里调试，带了一整条 `editorHostMode` 模态分支，不再需要
- 窗口可缩放（原版 style mask 固定死）

## 已知缺口

- **白名单只支持 IPv4**。兜底的 `block drop out quick all` 覆盖 IPv6，所以不会泄漏，
  但也没法放行任何 IPv6 目标
- **`utun0`~`utun9` 是写死的**。iCloud 私密代理、AirDrop 都会占 utun 号，
  VPN 落到 utun10+ 就会连不上网。pf.conf 语法应该支持 `utun*` 通配，待实测
