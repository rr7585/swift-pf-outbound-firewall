# PF Outbound Firewall

macOS 出站防火墙 / VPN 防 IP 泄漏开关（Kill-Switch），基于系统自带的 **PF**。
Swift 重写版，前身是 `legacy/PFOutboundFirewall.applescript`。

防护开启后默认阻断所有出站流量，只放行：

- 本机回环 `lo0`（用 `set skip` 完全跳过 pf）
- `utun0` ~ `utun31` 虚拟网卡（VPN / 代理加密后的流量）
- 白名单里的目的 IP / CIDR，**IPv4 与 IPv6 均可**（VPN 节点、局域网、必需的直连地址）

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

图标是代码画的，改了 `icon/make-icon.swift` 之后跑：

```bash
./icon/build-icon.sh   # 重新生成 icon/AppIcon.icns
./build.sh
```

`build.sh` 只在 `AppIcon.icns` 不存在时才自动调它，所以平时编译不会多花时间。

## 目录结构

| 路径 | 说明 |
| --- | --- |
| `app/Rules.swift` | 路径常量、PF 规则文本、白名单校验、root 侧脚本。纯函数，不执行任何东西 |
| `app/Core.swift` | 提权执行与状态查询 |
| `app/App.swift` | SwiftUI 界面 |
| `tests/RulesTests.swift` | `Rules.swift` 的测试，不依赖 XCTest / Xcode |
| `tests/cross-check-pf.sh` | 拿真 `pfctl` 核对白名单校验器的判断，手动跑 |
| `icon/make-icon.swift` | 图标画法（纯 CoreGraphics，不依赖设计工具） |
| `icon/build-icon.sh` | 生成 `icon/AppIcon.icns` |
| `legacy/PFOutboundFirewall.applescript` | AppleScriptObjC 原版，行为参照 |
| `legacy/pf-rules-standalone.sh` | 纯 shell 版，白名单写死在脚本里，`sudo` 跑一次当次生效 |

`Rules.swift` 只 import Foundation，所以 `test.sh` 能把它和测试文件一起编译成
一个可执行文件跑掉 —— 不用装 App，也不用 root。

## 权限模型

日常改白名单**不需要密码**。做法是 LaunchDaemon 的 `WatchPaths` 盯着
`allowlist.txt`，文件一变 launchd 就以 root 重跑守护脚本，由它校验并重载 PF。
GUI 那边只干一件事：把文本写进那个文件。

于是 root 侧不再接收任何来自界面的命令字符串，只读一个纯数据文件。

| 操作 | 要密码吗 |
| --- | --- |
| 改白名单并生效 | 不要 |
| 开启 / 关闭防护 | 要（`pfctl -e/-d` 和 `/var/run` 下的标记都归 root） |
| 安装 / 卸载 | 要 |

白名单文件是 `root:admin` `664`，所以本机管理员可写；目录本身仍是
`root:wheel` `755` —— root 执行的 `startup.sh` 就在里面，目录一旦可写，
谁都能把它换掉。

**代价**：GUI 写文件时没有 root 帮忙先校验，所以一份语法有问题的白名单
会真的落到磁盘上。但守护脚本加载前会 `pfctl -nf` 干跑，不通过就原样退出，
内核里还是上一份规则 —— 也就是写错只会「没生效」，不会把网络锁死。
界面侧本来也有逐行校验（走 `inet_pton`），这是第二道闸。

**旧版安装**（第一步那版，LaunchDaemon 没有 `WatchPaths`）会在界面上显示
一行橙色提示和「升级」按钮，点一下重跑安装脚本即可，配置不丢。

## 界面

- **安装并启用 / 保存并生效** — 写白名单、校验并加载 PF 规则
- **启用防护 / 关闭防护** — 临时开关，不删配置
- **卸载** — 停用 PF、移除开机自启、删除全部配置

白名单每行一个 IP 或网段，IPv4 / IPv6 都行，`#` 开头是注释：

```
# 香港节点
203.0.113.10
192.168.0.0/16
2001:4860:4860::8888
2606:4700::/32
fe80::1%en0
```

保存前逐行校验，有错会直接把光标定位到出错那行并选中。

## 安装后落地的文件

| 路径 | 说明 |
| --- | --- |
| `/Library/Application Support/PFOutboundFirewall/allowlist.txt` | 用户白名单（界面里编辑的那份） |
| `/Library/Application Support/PFOutboundFirewall/options.conf` | 高级选项开关，和白名单一样 admin 组可写 |
| `/Library/Application Support/PFOutboundFirewall/effective.txt` | 守护脚本合成的最终地址表 = 内置条目 + 用户白名单，pf 实际读这一份 |
| `/Library/Application Support/PFOutboundFirewall/rules.conf` | 生成的 PF 规则 |
| `/Library/Application Support/PFOutboundFirewall/startup.sh` | 守护脚本（开机 + 白名单变更共用） |
| `/Library/Application Support/PFOutboundFirewall/startup.log` | 守护脚本日志 |
| `/Library/Application Support/PFOutboundFirewall/apply-status.txt` | 守护脚本每次处理完的结果，GUI 读它做反馈 |
| `/Library/Application Support/PFOutboundFirewall/rules.loaded` | 上次加载进内核的规则集校验和，用来判断走快路径还是全量重载 |
| `/Library/LaunchDaemons/com.user.pf-outbound.plist` | LaunchDaemon（`RunAtLoad` + `WatchPaths`） |
| `/var/run/com.user.pf-outbound.disabled` | 关闭标记，重启后自动清空并恢复防护 |

安装、卸载、开关防护需要管理员密码；改白名单不需要。

## 实现上几个要记住的点

**提权**。`Core.swift` 的 `runAdmin` 把脚本写进当前用户专属的临时目录
（`/var/folders/…`，0700），再用 `osascript` 的 `do shell script … with
administrator privileges` 执行它。脚本路径通过 argv 传给 osascript，不拼进
AppleScript 字面量，所以只剩 shell 一层引用要管，由 `shellQuote` 负责 ——
白名单是用户输入，最终会落到 root 执行的脚本里，测试里专门有注入用例。

**守护脚本绝对不能写 `allowlist.txt`**。它是被 `WatchPaths` 监视的那个文件，
脚本碰一下就会把自己再次触发，无限循环烧 CPU。测试里锁了这条
（`testDaemonScriptNeverWritesAllowlist`）。同理，脚本的每条退出路径都必须写
`apply-status.txt`，否则 GUI 只能一直等到超时。

**局域网和 DHCP 做成高级选项，不要混进用户白名单**。这两类是几乎人人都要、
又跟具体用途无关的基础设施条目，塞在白名单里只会喧宾夺主。做成开关后，
守护脚本按开关把内置条目和用户白名单合成 `effective.txt`，pf 读的是合成结果。

合成表由守护脚本生成，**绝不能加进 `WatchPaths`** —— 否则又是自触发死循环。
被监视的是 `allowlist.txt` 和 `options.conf` 两个输入文件。

选项文件解析不出来时一律按「开」处理：文件损坏或来自旧版本时，
宁可多放行也不要突然把用户的局域网掐掉。

**开启防护前要预检**。默认路由走隧道、而白名单里一个公网地址都没有时，
开防护会连同通往 VPN 节点的连接一起阻断，隧道断开、整台机器失去网络。
这个坑在开发期间实际踩到过两次，所以界面在这种情况下会先警告再确认。

**改白名单走 `pfctl -T replace`，不要重载整个规则集**。守护脚本会先判断这次触发
是不是「只有白名单变了」—— pf 已启用、表已存在、且内核里加载的就是当前这份
`rules.conf`（比对校验和）。三个条件都满足就只换内核里那张表的内容，
不重载规则集也不清状态，**现有连接一条都不会断**。

实测：一个限速下载跑到一半时新增白名单条目，下载未中断，正常跑完。

只有条目被**移除**时才额外 `pfctl -F states` —— 光换表不够，已经建立的连接
靠旧状态还能继续跑，必须清状态才能真正切断，而这正是用户删条目时想要的效果。
前后两份表都取自 `pfctl -T show`，规范化方式一致，不会因为写法差异误判。

**`ThrottleInterval` 要调小**。launchd 默认同一个 job 两次启动至少隔 10 秒，
不改的话连着存两次白名单，第二次要等十秒才生效。设成 1。

**截断重写不是原子操作**。GUI 免密写白名单时不能用「临时文件 + 改名」那套
（那需要目录可写，而目录不能放权），只能原地截断后一次写完。所以守护脚本
开头 `sleep 0.3` 等内容落定，避开写到一半被触发。

**先校验再加载**。两条保存路径都不会把没验过的规则塞进内核：免密路径由守护脚本
在加载前 `pfctl -nf` 干跑；提权回退路径（旧版安装）则是先写临时文件、干跑通过了
才 `mv` 覆盖正式文件。跳过这步的话，一条笔误的规则就能把自己锁死。

**回环必须用 `set skip on lo0`，不能写 `pass out quick on lo0`**。

回环包会被 pf 看到两次：lo0 出站一次、lo0 入站一次。用 pass 规则时，出站 SYN 会带
`flags S/SA keep state` 建立状态；同一个 SYN 紧接着从 lo0 入站，pf 拿这条状态去匹配，
发现反方向来的不是 SYN-ACK 而是个裸 SYN，判定为序列异常直接丢掉。

表现是本机所有 TCP 服务都连不上（`curl 127.0.0.1` 超时），偏偏
`ping 127.0.0.1` 是通的 —— ICMP 的状态跟踪宽松得多。这个不一致很有迷惑性，
容易往「服务没监听」或者 IPv6 的方向排查。

`set skip` 让 pf 在 lo0 上完全不做检查也不建状态。回环流量出不了本机，
不存在泄漏问题，跳过是安全的；OpenBSD 自带的 pf.conf 就是这么写的。

**接口名必须枚举，`utun*` 通配在 macOS 上没用**。`pfctl` 收这个语法、
`pfctl -nvf` 也会把它原样打印出来，看上去完全正常，但运行时**一个包都匹配不上**。

只看解析结果会被骗过去，要看规则命中计数（`pfctl -vsr`）才能发现。实测同一份
规则集里两条并排放：

```
pass out quick on utun* all   [ Evaluations: 1921  Packets: 0    ]
pass out quick on utun4 all   [ Evaluations: 1921  Packets: 1422 ]
```

接口组写法（`on utun`）同理 —— 语法收，运行时不匹配，macOS 的 `ifconfig`
本来也没有 groups 这个概念。

所以只能枚举到 `maxUtunIndex`（当前 31）。有上限意味着编号更大的 utun 不被放行，
但这个失败方向是安全的：表现为「VPN 连不上」而不是「真实 IP 泄漏」。
32 个对实际使用绰绰有余 —— macOS 分配 utun 时取最小空闲编号，
要突破得同时存在 32 条隧道。

**IPv4 和 IPv6 共用一张表**。pf 的 table 可以混放两种地址，
`pass out quick to <表>` 不指定地址族时两种都匹配，兜底的 block 同理。
所以不需要按族分两套规则。

**白名单校验比 pf 严，这是故意的**。校验器走严格的 `inet_pton`，pf 走宽松的
`inet_aton` 加域名解析。差异都在「我们拒、pf 收」这一侧：

| 写法 | pf 的理解 | 为什么我们不收 |
| --- | --- | --- |
| `1.2.3` | `1.2.0.3` | 简写含义与直觉相反 |
| `16909060` | `1.2.3.4` | 同上 |
| `01.2.3.4` | `1.2.3.4` | 这里是十进制，但别的工具会按八进制读成 8 |
| `example.com` | 加载时解析一次 | 开机加载规则时 DNS 正被上一版规则挡着，解析失败会让整条规则集加载失败 |

`tests/cross-check-pf.sh` 把每条样本真喂给 `pfctl -nf` 比对两边结论，
判定是单向的：**校验器接受的，pf 必须也接受**；反过来的分歧要显式登记在
脚本的 `KNOWN_STRICTER` 里。

**`block` 必须是最后一条**。pf 的 `quick` 先匹配先生效，兜底的
`block drop out quick all` 跑到前面去就等于全断网。测试里锁了这条。

**`pfctl -f` 要重试**。macOS 偶尔有别的系统服务占着 PF 事务锁，
直接加载会报 `DIOCXCOMMIT: Resource busy`，重试十次基本都能过。

**安装时不要并发加载 PF**。`launchctl bootstrap` 的 `RunAtLoad` 已经会加载一次，
安装脚本再来一次就会撞锁。所以安装脚本改成轮询 `installed.ok`
（开机脚本最后一步才 touch），最多等 10 秒。

**关闭标记放 `/var/run`**。重启后自动清空，开机任务重新开启防护 ——
kill-switch 不应该因为你昨天临时关过就一直关着。

**图标要留白**。Big Sur 之后的 App 图标不铺满画布：1024 的画布里圆角方块只占 824，
四周留白。铺满的话图标在 Dock 里会比旁边的大一圈，非常显眼。

**窗口尺寸别用 `.windowResizability(.contentMinSize)`**。它把窗口最小尺寸钉在
内容最小尺寸上，而 `AllowlistEditor` 包着的 NSScrollView 会报一个很大的固有尺寸，
最小宽度会变成 900pt，小屏上缩不小。更隐蔽的是「未安装」状态下编辑器压根没显示，
`if/else` 的另一个分支照样参与这个计算。

## 排障

```bash
sudo pfctl -s info                      # PF 是否 Enabled
sudo pfctl -s rules                     # 当前规则
sudo pfctl -t vpn_allowlist -T show     # 白名单表
cd /Library/Application\ Support/PFOutboundFirewall
cat startup.log        # 守护脚本上一次的完整输出
cat apply-status.txt   # 第一行 ok/fail，第二行说明
ls -l allowlist.txt    # 应为 -rw-rw-r-- root admin，否则免密保存走不通
```

被锁死且界面也打不开时：

```bash
sudo pfctl -d                                        # 临时关闭 PF
sudo launchctl bootout system/com.user.pf-outbound   # 停掉开机自启
```

## 与 AppleScript 原版的差异

- **改白名单不再需要密码**（原版每次保存都弹授权框）
- **白名单支持 IPv6**（原版只认 IPv4）
- **utun 枚举到 31**（原版只到 utun9，VPN 落到 utun10+ 就断网）
- 启用防护从两次提权合成一次（原版 `saveAllowlist` + `enable` 各弹一次密码）
- 原版手搓了一整套 `configureMainMenu` 才让 ⌘C/⌘V 能用，SwiftUI 自带标准编辑菜单，全删了
- 原版为了能在脚本编辑器里调试，带了一整条 `editorHostMode` 模态分支，不再需要
- 窗口可缩放（原版 style mask 固定死）

## 已知取舍

- **放行的是所有 utun 隧道**，不只是你的 VPN。iCloud 私密代理之类的隧道
  起来了也会被放行。对 kill-switch 来说这是有意的 —— 目的是「不许绕过隧道
  直连」，而不是「只许用某一条隧道」
- **白名单不支持域名**，理由见上面的表
- **规则集是全量替换**。加载时会盖掉 `/etc/pf.conf` 里系统自带的主规则集，
  卸载时用 `pfctl -F all` 清掉。如果你另外装了依赖 pf 的软件（部分 VPN 客户端
  会自己写 pf 规则），两边会互相覆盖
