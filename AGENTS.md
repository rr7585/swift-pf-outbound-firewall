# 项目协作规范

macOS 出站防火墙 / VPN 防 IP 泄漏开关，基于系统自带的 pf。

上级 `../AGENTS.md` 的「称谓约定」和「验证与提交」同样适用，其余章节属于另一个
项目，不适用于这里。本文件只写这个项目特有的约束，以及踩过的坑。

## 这个项目最容易出的事

**改错了会让整台机器断网。** 它是 default deny 的出站防火墙，一条规则写错就是
全网不通，而且此时你没法再联网查资料、装东西、或者跟主人沟通。所有动真实系统的
操作都按这个前提设计：

- **动系统的命令必须是一条原子命令。** 从"规则生效"到"验证通过"之间不能有第二次
  交互的机会 —— 断网期间任何需要往返的步骤都会卡死。先把要做的全部写进一个脚本，
  一次跑完。
- **带自动回滚。** 脚本自己验证连通性，不通就在同一个脚本里恢复原状。不要指望
  出事之后还能再跑一条命令。
- **先留救急出口。** `sudo pfctl -d` + `sudo launchctl bootout system/com.user.pf-outbound`
  能恢复网络，动手前确认主人知道这两条。

**验证要验「该通的也通」，不只是「该挡的挡住」。** 回环 TCP 全挂那次，防护、隧道、
局域网三项都验过了，唯独没验本机服务 —— 而那恰恰是坏的那一项。安装后的自检至少要
覆盖：隧道外网、本机回环、局域网、以及一条应当被挡的直连。

## pf 的坑

**解析通过不等于运行时匹配。** 这是这个项目最贵的一课。`pfctl -nf` 通过、
`pfctl -nvf` 把规则原样打印出来，都不能证明它真的会匹配到包。唯一的证据是
**规则命中计数**：

```bash
sudo pfctl -vsr    # 看每条规则的 Evaluations / Packets
```

已知会骗人的写法：

| 写法 | 解析 | 运行时 |
| --- | --- | --- |
| `on utun*` 接口通配 | 通过 | **一个包都不匹配** |
| `on utun` 接口组 | 通过 | 同上，macOS 的 ifconfig 也没有 groups |

所以接口只能枚举（见 `maxUtunIndex`）。枚举有上限，但失败方向是安全的：
表现为「编号更大的隧道连不上」，而不是「真实 IP 泄漏」。

**回环必须 `set skip on lo0`，不能用 `pass out quick on lo0`。** 回环包会被 pf
看到两次（出站一次、入站一次），pass 规则会在出站 SYN 上建状态，同一个 SYN 入站时
被判为序列异常丢弃 —— 本机 TCP 服务全部连不上，而 `ping 127.0.0.1` 照样通，
症状会把人往错误方向引。

**兜底 `block` 必须是最后一条。** pf 的 `quick` 先匹配先生效，跑到前面去就是全断网。

**`pfctl -f` 要重试。** 偶尔有别的系统服务占着 PF 事务锁，会报
`DIOCXCOMMIT: Resource busy`，重试十次基本都能过。

**安装时不要并发加载 PF。** `launchctl bootstrap` 的 `RunAtLoad` 已经会加载一次，
安装脚本再来一次就撞锁。改成轮询 `installed.ok`。

**macOS 没有 `pflog0`。** `log` 关键字能解析，但拿不到日志接口，所以「记录被阻断的
连接」这条路在 pf 上走不通。要做按应用的逐流控制只能上 NetworkExtension 的
`NEFilterDataProvider`，那需要付费开发者账号的 networkextension 权限和系统扩展。

## 架构约束

- **`app/Rules.swift` 只产生字符串，不执行任何命令。** 它只 import Foundation，
  所以 `tests/` 能直接把它编进测试程序，不用装 App、不用 root。新增规则或脚本逻辑
  一律放这里，保持可测。
- **提权只走 `runAdmin`。** 脚本先落到用户专属临时目录，路径通过 argv 传给
  `osascript`，不拼进 AppleScript 字面量。所有外部输入（白名单正文）必须过
  `shellQuote` —— 那些内容最终由 root 执行，测试里有专门的注入用例。
- **守护脚本绝不能写 `allowlist.txt` 或 `options.conf`。** 它们被 `WatchPaths`
  监视，脚本碰一下就自触发，无限循环。合成表 `effective.txt` 由守护脚本生成，
  因此**不得**加进 `WatchPaths`。
- **守护脚本每条退出路径都要写 `apply-status.txt`。** GUI 靠它的 mtime 变化判断
  处理完成，漏一条路径界面就只能干等到超时。
- **白名单文件是 `root:admin 664`，目录保持 `root:wheel 755`。** 目录里放着 root
  要执行的 `startup.sh`，目录一旦可写，谁都能把它换掉。
- **改白名单走 `pfctl -T replace`，不要重载整个规则集。** 重载会清状态、掐断所有
  现有连接。只有条目被**移除**时才额外清状态。

## SwiftUI 的坑

这台机器没有录屏权限，截不了图。**唯一的可视反馈是 `tools/render-ui.swift`**，
它用 `ImageRenderer` 把界面离屏渲染成 PNG，深浅两套外观都出图。改界面后跑它，
然后真的去看那些图。

`ImageRenderer` 渲染不了 AppKit 支撑的视图，会画成黄色禁止符占位：
`Form(.grouped)`、`ScrollView`、`Table`、`Picker(.segmented)`、`Toggle`、
以及任何 `NSViewRepresentable`。**布局因此一律手写卡片**（见 `Card`），
不用 `Form` —— 既可控，又能离屏验证。

**渲染只能看出「画成什么样」，看不出「能不能点」。** 热区问题要用临时染色
（给按钮加个 `.background(Color.red.opacity(0.25))`）渲染出来确认，之后记得删掉。
已知：`DisclosureGroup` 在 macOS 上只有小三角是热区，标题文字点不动。

**窗口尺寸不要指望 SwiftUI。** `.windowResizability(.contentMinSize)` 会把最小宽度
钉到 900pt（`NSViewRepresentable` 报了个很大的固有尺寸，而且未显示的 `if/else`
分支照样参与计算）；去掉之后 `.defaultSize` 和 `.frame(idealHeight:)` 又都被忽略。
现在用 `WindowConfigurator` 在首次打开时 `setContentSize` 一次，之后交给系统记忆。
判断「是否首次」用自己记的标记，不能读 AppKit 的 `NSWindow Frame` 键 —— 那个回调
执行时 SwiftUI 还没分配 `frameAutosaveName`。

**测窗口尺寸前先确认偏好已清干净。** `defaults delete` 和被 kill 的进程写回偏好
之间有竞态，kill 和 delete 写在同一条命令里往往清不掉，会让人误以为是代码问题。

## 验证与提交

改动后按需要跑：

```bash
./test.sh                  # 单元测试，不需要 root、不需要安装
./tests/cross-check-pf.sh  # 拿真 pfctl 核对白名单校验器
./build.sh                 # 编译出 .app
./icon/build-icon.sh       # 只在改了图标画法时
```

改了规则生成或 root 脚本，额外做三件事：

1. `sh -n` 检查生成出来的每个脚本（语法错误在真机上代价很高）
2. `plutil -lint` 检查生成的 plist
3. 拿假的 `pfctl` 在沙箱里跑一遍守护脚本的各条分支（正常 / 语法错误 / 防护已关闭 /
   加载失败 / 仅新增 / 有删除）

**提交匿名**：author/committer 用 `anonymous <anonymous@localhost>`（本仓库已在
本地 git 配置里设好），commit message 不出现 AI 署名、工具名、真实姓名、邮箱、
本机路径、用户名、主机名。提交信息用简洁的英文 conventional commit 格式。

**示例地址一律用文档保留段**（RFC 5737 的 `192.0.2.0/24`、`198.51.100.0/24`、
`203.0.113.0/24`）。代码、注释、README、测试样本里都不写主人真实的 VPN 节点、
内网地址或隧道地址 —— 这类值提交一次就永久留在历史里。

`build/` 是产物，不进版本库。

## 已知取舍

- **放行的是所有 utun 隧道**，不只是主人的 VPN。对 kill-switch 来说这是有意的：
  目的是「不许绕过隧道直连」，而不是「只许用某一条隧道」。
- **白名单不支持域名。** pf 收域名，但它在**加载时**解析一次 —— 而开机加载规则时
  DNS 正被上一版规则挡着，解析失败会让整条规则集加载不上。
- **连接面板是尽力而为的。** pf 没有进程概念，归属靠 `lsof` 快照；不提权只看得到
  当前用户的进程；短连接可能在两次采样之间就结束了。
- **规则集是全量替换**，会盖掉 `/etc/pf.conf` 的主规则集。跟自己写 pf 规则的软件
  会互相覆盖。
