import Foundation

// PF 出站防火墙 —— 路径常量、PF 规则文本、白名单校验、root 侧 shell 脚本。
//
// 本文件不 import AppKit，也不执行任何命令：全是纯函数，输入什么就返回什么字符串。
// 所以 tests/ 可以直接把它编译进测试程序，不需要装 App、不需要 root。

// ============================================================================
// 路径与服务标识
// ============================================================================
enum Paths {
    static let dataDir = "/Library/Application Support/PFOutboundFirewall"
    static let allowlist = dataDir + "/allowlist.txt"
    static let rules = dataDir + "/rules.conf"
    static let startup = dataDir + "/startup.sh"
    static let installMarker = dataDir + "/installed.ok"
    static let startupLog = dataDir + "/startup.log"
    /// 守护进程每次处理完写在这里，GUI 靠它知道免密保存到底生效没有。
    static let applyStatus = dataDir + "/apply-status.txt"
    /// 上次成功加载进内核的那份 rules.conf 的校验和。
    /// 用来判断这次触发只是白名单变了（快路径），还是规则集本身变了（全量重载）。
    static let loadedRulesHash = dataDir + "/rules.loaded"
    // /var/run 重启后清空；开机任务会重新开启 PF，所以“已关闭”不应跨重启保留。
    static let disabledMarker = "/var/run/com.user.pf-outbound.disabled"
    static let daemonPlist = "/Library/LaunchDaemons/com.user.pf-outbound.plist"
    static let serviceID = "com.user.pf-outbound"
}

// ============================================================================
// shell 拼接
// ============================================================================

/// 单引号包裹，内部单引号换成 '\'' —— 任意字节都能安全传给 sh。
/// root 要执行这些脚本，所有外部输入（白名单正文）都必须经过这里。
func shellQuote(_ text: String) -> String {
    "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

/// 生成一条“把 content 原样写进 path”的命令。
/// 用 printf '%s' 而不是 heredoc：内容里出现什么分隔符都不会提前结束。
func shellWrite(_ content: String, to path: String) -> String {
    "/usr/bin/printf '%s' \(shellQuote(content)) > \(shellQuote(path))"
}

// ============================================================================
// PF 规则
// ============================================================================

/// 虚拟网卡放行到 utunN 为止。
///
/// 本来想用 `utun*` 通配一劳永逸，实测行不通：macOS 的 pf 能解析这个写法、
/// 也会原样保留在规则集里，但运行时一个包都匹配不上。用规则命中计数验过 ——
/// `on utun*` 评估 1921 次命中 0 个包，同一时刻 `on utun4` 命中 1422 个包。
/// 接口组（`on utun`）同理，语法收但运行时不匹配，macOS 的 ifconfig 也没有
/// groups 这个概念。所以只能老老实实枚举。
///
/// 枚举有上限就意味着编号更大的 utun 不被放行。这个方向是安全的 ——
/// 失败表现为「VPN 连不上」而不是「真实 IP 泄漏」。32 个对实际使用足够：
/// iCloud 私密代理、AirDrop 加几条 VPN 也到不了这个数。
let maxUtunIndex = 31

/// 防护规则：放行 lo0、utun 虚拟网卡和白名单目的地址，其余出站一律丢弃。
/// allowlistPath 指向 pf 自己去读的表文件，所以校验新白名单时可以先指到临时文件。
///
/// 表里 IPv4 和 IPv6 可以混着放，`pass out quick to <表>` 不指定地址族时
/// 两种都匹配；兜底的 block 同理，所以 IPv6 也不会泄漏。
func pfRules(allowlistPath: String) -> String {
    let utuns = (0...maxUtunIndex).map { "utun\($0)" }.joined(separator: " ")
    let lines = [
        // 回环必须用 set skip 整个跳过 pf，不能写成 pass out quick on lo0。
        //
        // 回环包会被 pf 看到两次：lo0 出站一次、lo0 入站一次。用 pass 规则时，
        // 出站 SYN 会带 flags S/SA keep state 建立状态；同一个 SYN 紧接着从 lo0
        // 入站，pf 拿这条状态去匹配，发现反方向来的不是 SYN-ACK 而是个裸 SYN，
        // 判定为序列异常直接丢掉 —— 表现就是本机 TCP 服务全连不上，
        // 而 ICMP（ping 127.0.0.1）因为状态跟踪宽松反而是通的，很有迷惑性。
        //
        // set skip 让 pf 在 lo0 上完全不做检查也不建状态。回环流量出不了本机，
        // 不存在泄漏问题，跳过是安全的。OpenBSD 自带的 pf.conf 也是这么写的。
        "set skip on lo0",
        "table <vpn_allowlist> persist file \"\(allowlistPath)\"",
        // 花括号由 pfctl 展开成一条条独立规则，和手写 32 行等价，只是源文件短些。
        "pass out quick on { \(utuns) } all",
        "pass out quick to <vpn_allowlist>",
        "block drop out quick all",
    ]
    return lines.joined(separator: "\n") + "\n"
}

/// macOS 偶尔有别的系统服务短暂占着 PF 事务锁，直接 -f 会报
/// DIOCXCOMMIT: Resource busy；重试十次基本都能过去。
///
/// onFailure 是重试耗尽后要执行的语句。守护脚本要在这里补一条状态记录，
/// 别的地方直接退出就行。整条命令是单个 shell 语句，可以塞进一行脚本里。
func pfLoadCommand(rulesPath: String = Paths.rules, onFailure: String = "exit 1") -> String {
    "attempt=0; until /sbin/pfctl -f \(shellQuote(rulesPath)); do "
        + "attempt=$((attempt + 1)); "
        + "if [ \"$attempt\" -ge 10 ]; then \(onFailure); fi; "
        + "/bin/sleep 0.2; done"
}

// ============================================================================
// root 侧脚本
// ============================================================================

/// 保存白名单。apply=false 时只落盘不加载（防护已关闭时不该把规则塞回内核）。
///
/// 顺序是有讲究的：先把新白名单写到临时文件、用 pfctl -nf 拿临时规则试解析，
/// 通过了才 mv 覆盖正式文件。否则一条笔误的规则会把自己的网络彻底锁死。
func saveScript(listText: String, apply: Bool) -> String {
    let tempList = Paths.dataDir + "/allowlist.new"
    let tempRules = Paths.dataDir + "/rules.new"
    var lines = [
        "set -e",
        "/bin/mkdir -p \(shellQuote(Paths.dataDir))",
        "/bin/chmod 755 \(shellQuote(Paths.dataDir))",
        shellWrite(listText, to: tempList),
        shellWrite(pfRules(allowlistPath: tempList), to: tempRules),
        "/sbin/pfctl -nf \(shellQuote(tempRules)) >/dev/null",
        "/bin/mv \(shellQuote(tempList)) \(shellQuote(Paths.allowlist))",
        shellWrite(pfRules(allowlistPath: Paths.allowlist), to: Paths.rules),
        "/bin/rm -f \(shellQuote(tempRules))",
        // mv 会把临时文件的属主权限带过来，这里补回 admin 组可写，
        // 否则一次提权保存之后免密保存就失效了。
        "/usr/sbin/chown root:admin \(shellQuote(Paths.allowlist))",
        "/bin/chmod 664 \(shellQuote(Paths.allowlist))",
        "/bin/chmod 600 \(shellQuote(Paths.rules))",
    ]
    if apply {
        lines.append(pfLoadCommand())
        lines.append("/sbin/pfctl -F states")
    }
    return lines.joined(separator: "\n") + "\n"
}

/// 守护脚本，由 LaunchDaemon 以 root 执行。两种触发方式共用同一份逻辑：
///
/// - `RunAtLoad`：开机时加载规则并启用 PF
/// - `WatchPaths`：白名单文件一变就重新加载
///
/// 后者是免密保存的关键 —— GUI 只要能写 allowlist.txt，剩下的 root 活由
/// 这个脚本干，界面侧一次 pfctl 都不用碰。
///
/// 两条铁律：
/// 1. **绝对不能写 allowlist.txt**，否则会把自己再次触发，无限循环。
/// 2. 每条退出路径都要写 apply-status.txt，否则 GUI 只能一直等到超时。
func daemonScript() -> String {
    let statusPath = shellQuote(Paths.applyStatus)
    let statusTempPath = shellQuote(Paths.applyStatus + ".new")
    let rulesPath = shellQuote(Paths.rules)
    let listPath = shellQuote(Paths.allowlist)
    let hashPath = shellQuote(Paths.loadedRulesHash)
    let beforePath = shellQuote(Paths.dataDir + "/table.before")
    let afterPath = shellQuote(Paths.dataDir + "/table.after")
    let loadRules = pfLoadCommand(onFailure: "report fail \"加载 PF 规则失败\"; exit 1")
    return """
    #!/bin/sh
    exec > \(shellQuote(Paths.startupLog)) 2>&1
    echo "=== $(/bin/date) ==="

    # WatchPaths 可能在 GUI 还没写完时就触发（截断+写入不是原子操作），
    # 停一下让内容落定再读。开机那条路径上这 0.3 秒无所谓。
    /bin/sleep 0.3

    # 每条路径都要落状态，GUI 靠 apply-status.txt 的 mtime 变化判断处理完了。
    report() {
        /usr/bin/printf '%s\\n%s\\n' "$1" "$2" > \(statusTempPath)
        /bin/mv \(statusTempPath) \(statusPath)
        /bin/chmod 644 \(statusPath)
    }

    # 先干跑校验。不通过就原样退出 —— 内核里还是上一份规则，
    # 也就是说白名单写错了只会“没生效”，不会把网络锁死。
    if ! /sbin/pfctl -nf \(rulesPath); then
        report fail "白名单语法有误，已保持原有规则"
        exit 1
    fi

    # 用户主动关过防护，这时改白名单只存不加载，不把防护偷偷打开。
    if [ -f \(shellQuote(Paths.disabledMarker)) ]; then
        report ok "防护当前已关闭，白名单已保存但未加载"
        exit 0
    fi

    # 走不走快路径：pf 已启用、表已存在、且内核里加载的就是当前这份 rules.conf。
    # 三个条件都满足，说明这次触发只可能是白名单变了，不必重载整个规则集。
    rules_hash=$(/sbin/md5 -q \(rulesPath) 2>/dev/null)
    fast=0
    if /sbin/pfctl -s info 2>/dev/null | /usr/bin/grep -q '^Status: Enabled' \\
       && /sbin/pfctl -t vpn_allowlist -T show >/dev/null 2>&1 \\
       && [ -n "$rules_hash" ] \\
       && [ "$rules_hash" = "$(/bin/cat \(hashPath) 2>/dev/null)" ]; then
        fast=1
    fi

    if [ "$fast" = 1 ]; then
        # 快路径：只把内核里那张表的内容换掉。
        # 不碰规则集、不清状态，所以现有连接一条都不会断。
        /sbin/pfctl -t vpn_allowlist -T show 2>/dev/null \\
            | /usr/bin/sed 's/^[[:space:]]*//' | /usr/bin/sort > \(beforePath)
        if ! /sbin/pfctl -t vpn_allowlist -T replace -f \(listPath); then
            report fail "更新白名单失败"
            exit 1
        fi
        /sbin/pfctl -t vpn_allowlist -T show 2>/dev/null \\
            | /usr/bin/sed 's/^[[:space:]]*//' | /usr/bin/sort > \(afterPath)

        # 前后都取自 pfctl 自己的输出，规范化方式一致，不会因为写法差异误判。
        removed=$(/usr/bin/comm -23 \(beforePath) \(afterPath))
        /bin/rm -f \(beforePath) \(afterPath)
        /usr/bin/touch \(shellQuote(Paths.installMarker))

        if [ -n "$removed" ]; then
            # 有条目被删掉。光换表不够 —— 已经建立的连接靠旧状态还能继续跑，
            # 必须清状态才能真正切断，这正是用户删条目时想要的效果。
            /sbin/pfctl -F states
            report ok "白名单已更新，移除的地址已断开"
        else
            report ok "白名单已更新，现有连接未受影响"
        fi
        exit 0
    fi

    # 全量路径：开机，或者规则集本身变了（装新版、改了规则模板）。
    \(loadRules)
    if ! /sbin/pfctl -s info 2>/dev/null | /usr/bin/grep -q '^Status: Enabled'; then
        /sbin/pfctl -e
    fi
    /sbin/pfctl -F states
    /usr/bin/printf '%s' "$rules_hash" > \(hashPath)
    /usr/bin/touch \(shellQuote(Paths.installMarker))
    report ok "已生效"

    """
}

func daemonPlist() -> String {
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
    <key>Label</key><string>\(Paths.serviceID)</string>
    <key>ProgramArguments</key><array><string>/bin/sh</string><string>\(Paths.startup)</string></array>
    <key>RunAtLoad</key><true/>
    <key>WatchPaths</key><array><string>\(Paths.allowlist)</string></array>
    <key>ThrottleInterval</key><integer>1</integer>
    </dict></plist>

    """
}

/// 安装并启用：写配置 → 装 LaunchDaemon → bootstrap 触发首次加载。
///
/// bootstrap 的 RunAtLoad 已经负责加载 PF，这里不能再并发跑第二次 pfctl -f。
/// 所以改成轮询 installed.ok（开机脚本最后一步才 touch），最多等 10 秒；
/// 等不到就把 startup.log 吐到 stderr，让 GUI 显示真正的失败原因。
func installScript() -> String {
    let lines = [
        "set -e",
        "/bin/mkdir -p \(shellQuote(Paths.dataDir))",
        "/bin/chmod 755 \(shellQuote(Paths.dataDir))",
        "/bin/rm -f \(shellQuote(Paths.installMarker))",
        // 清掉旧哈希，保证装完第一次跑守护脚本走全量加载而不是快路径
        "/bin/rm -f \(shellQuote(Paths.loadedRulesHash))",
        "/usr/bin/touch \(shellQuote(Paths.allowlist))",
        shellWrite(pfRules(allowlistPath: Paths.allowlist), to: Paths.rules),
        // 白名单交给 admin 组可写，GUI 就能免密改它，由 WatchPaths 触发重载。
        // 目录本身保持 root:wheel 755 —— root 执行的 startup.sh 就在里面，
        // 目录一旦可写，任何人都能把它换掉。
        "/usr/sbin/chown root:admin \(shellQuote(Paths.allowlist))",
        "/bin/chmod 664 \(shellQuote(Paths.allowlist))",
        "/bin/chmod 600 \(shellQuote(Paths.rules))",
        shellWrite(daemonScript(), to: Paths.startup),
        "/bin/chmod 700 \(shellQuote(Paths.startup))",
        shellWrite(daemonPlist(), to: Paths.daemonPlist),
        "/bin/chmod 644 \(shellQuote(Paths.daemonPlist))",
        "/bin/launchctl bootout system/\(Paths.serviceID) 2>/dev/null || true",
        "/bin/launchctl bootstrap system \(shellQuote(Paths.daemonPlist))",
        "count=0",
        "while [ ! -f \(shellQuote(Paths.installMarker)) ] && [ \"$count\" -lt 100 ]; do "
            + "/bin/sleep 0.1; count=$((count + 1)); done",
        "if [ ! -f \(shellQuote(Paths.installMarker)) ]; then "
            + "/bin/cat \(shellQuote(Paths.startupLog)) >&2 2>/dev/null || true; exit 1; fi",
    ]
    return lines.joined(separator: "\n") + "\n"
}

/// 卸载：停服务、清 PF、删掉所有落地文件。每一步都容错，半装状态也能卸干净。
func uninstallScript() -> String {
    let lines = [
        "/bin/launchctl bootout system/\(Paths.serviceID) 2>/dev/null || true",
        "/sbin/pfctl -F all 2>/dev/null || true",
        "/sbin/pfctl -d 2>/dev/null || true",
        "/bin/rm -rf \(shellQuote(Paths.dataDir))",
        "/bin/rm -f \(shellQuote(Paths.daemonPlist))",
    ]
    return lines.joined(separator: "\n") + "\n"
}

/// 关闭防护：停 PF 并写下关闭标记。标记在 /var/run，重启后自动恢复防护。
func disableScript() -> String {
    let lines = [
        "set -e",
        "if /sbin/pfctl -s info 2>/dev/null | /usr/bin/grep -q '^Status: Enabled'; then /sbin/pfctl -d; fi",
        "/sbin/pfctl -F states",
        "/usr/bin/touch \(shellQuote(Paths.disabledMarker))",
    ]
    return lines.joined(separator: "\n") + "\n"
}

/// 开启防护：加载规则、确保 PF 已启用、清掉关闭标记。
/// flush states 是必须的，否则关闭期间建立的直连会一直活着。
func enableScript() -> String {
    let lines = [
        "set -e",
        pfLoadCommand(),
        "if ! /sbin/pfctl -s info 2>/dev/null | /usr/bin/grep -q '^Status: Enabled'; then /sbin/pfctl -e; fi",
        "/sbin/pfctl -F states",
        "/bin/rm -f \(shellQuote(Paths.disabledMarker))",
    ]
    return lines.joined(separator: "\n") + "\n"
}

// ============================================================================
// 白名单校验
// ============================================================================

/// 一条不合法的白名单记录。range 是它在整段文本里的 UTF-16 范围，
/// 给 NSTextView 选中用（NSRange 按 UTF-16 计长，不能用 Character 数）。
struct AllowlistIssue {
    let lineNumber: Int
    let text: String
    let range: NSRange
}

/// 判断地址属于哪个族，不是合法地址返回 nil。
///
/// 用系统的 inet_pton 而不是手搓正则：IPv6 的正则想写对太难（压缩零段、
/// 内嵌 IPv4、各种边界），而最终要过的本来就是 pf 那一关，pf 用的就是这套解析。
private func addressFamily(of text: String) -> Int32? {
    var v4 = in_addr()
    if text.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 { return AF_INET }
    var v6 = in6_addr()
    if text.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 { return AF_INET6 }
    return nil
}

/// IPv4 的某一段是否带前导零。
///
/// libc 和 pf 都按十进制读（`010` → `10`），所以不会真的解析错，但
/// `ping`、部分解析器会按八进制读成 8 —— 同一份白名单换个工具含义就变了。
/// 与其留这个坑，不如让用户写明确。
private func hasLeadingZeroOctet(_ text: String) -> Bool {
    text.split(separator: ".", omittingEmptySubsequences: false)
        .contains { $0.count > 1 && $0.hasPrefix("0") }
}

/// 一条白名单记录是否合法：IPv4 或 IPv6 地址，可带 `/前缀长度`。
///
/// 比 pf 略严一点：pf 收前导零，这里不收，理由见上。
/// 其余一律跟 pf 保持一致，包括 `fe80::1%en0` 这种带 scope 的写法。
func isValidAllowlistEntry(_ text: String) -> Bool {
    let parts = text.components(separatedBy: "/")
    guard parts.count <= 2, let family = addressFamily(of: parts[0]) else { return false }
    if family == AF_INET, hasLeadingZeroOctet(parts[0]) { return false }
    guard parts.count == 2 else { return true }

    let prefixText = parts[1]
    guard !prefixText.isEmpty,
          prefixText.allSatisfy({ $0.isASCII && $0.isNumber }),
          let prefix = Int(prefixText) else { return false }
    return prefix <= (family == AF_INET ? 32 : 128)
}

/// 逐行校验，返回第一处错误；全部合法返回 nil。
/// 空行和 # 开头的注释行跳过 —— pf 的 table 文件本身就支持这两种。
func validateAllowlist(_ text: String) -> AllowlistIssue? {
    var offset = 0
    for (index, rawLine) in text.components(separatedBy: "\n").enumerated() {
        let rawLength = rawLine.utf16.count
        let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
        if !trimmed.isEmpty, !trimmed.hasPrefix("#"), !isValidAllowlistEntry(trimmed) {
            return AllowlistIssue(
                lineNumber: index + 1,
                text: trimmed,
                range: NSRange(location: offset, length: rawLength))
        }
        offset += rawLength + 1  // +1 是被 components 吃掉的那个换行
    }
    return nil
}
