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

/// 防护规则：放行 lo0、utun0~9 和白名单目的地址，其余出站一律丢弃。
/// allowlistPath 指向 pf 自己去读的表文件，所以校验新白名单时可以先指到临时文件。
func pfRules(allowlistPath: String) -> String {
    var lines = [
        "table <vpn_allowlist> persist file \"\(allowlistPath)\"",
        "pass out quick on lo0 all",
    ]
    for index in 0...9 {
        lines.append("pass out quick on utun\(index) all")
    }
    lines.append("pass out quick to <vpn_allowlist>")
    lines.append("block drop out quick all")
    return lines.joined(separator: "\n") + "\n"
}

/// macOS 偶尔有别的系统服务短暂占着 PF 事务锁，直接 -f 会报
/// DIOCXCOMMIT: Resource busy；重试十次基本都能过去。
func pfLoadCommand(rulesPath: String = Paths.rules) -> String {
    "attempt=0; until /sbin/pfctl -f \(shellQuote(rulesPath)); do "
        + "attempt=$((attempt + 1)); "
        + "if [ \"$attempt\" -ge 10 ]; then exit 1; fi; "
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
        "/bin/chmod 644 \(shellQuote(Paths.allowlist))",
        "/bin/chmod 600 \(shellQuote(Paths.rules))",
    ]
    if apply {
        lines.append(pfLoadCommand())
        lines.append("/sbin/pfctl -F states")
    }
    return lines.joined(separator: "\n") + "\n"
}

/// 开机加载脚本，由 LaunchDaemon 以 root 执行。
/// 全程输出重定向到 startup.log，安装失败时 GUI 会把它读出来显示。
func startupScript() -> String {
    """
    #!/bin/sh
    exec > \(shellQuote(Paths.startupLog)) 2>&1
    set -e
    /bin/rm -f \(shellQuote(Paths.installMarker))
    /sbin/pfctl -nf \(shellQuote(Paths.rules))
    \(pfLoadCommand())
    if ! /sbin/pfctl -s info 2>/dev/null | /usr/bin/grep -q '^Status: Enabled'; then /sbin/pfctl -e; fi
    /sbin/pfctl -F states
    /bin/rm -f \(shellQuote(Paths.disabledMarker))
    /usr/bin/touch \(shellQuote(Paths.installMarker))

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
        "/usr/bin/touch \(shellQuote(Paths.allowlist))",
        shellWrite(pfRules(allowlistPath: Paths.allowlist), to: Paths.rules),
        "/bin/chmod 644 \(shellQuote(Paths.allowlist))",
        "/bin/chmod 600 \(shellQuote(Paths.rules))",
        shellWrite(startupScript(), to: Paths.startup),
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

/// 逐行校验，返回第一处错误；全部合法返回 nil。
/// 空行和 # 开头的注释行跳过 —— pf 的 table 文件本身就支持这两种。
func validateAllowlist(_ text: String) -> AllowlistIssue? {
    let octet = "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
    let pattern = "^(?:\(octet)\\.){3}\(octet)(?:/(?:3[0-2]|[12]?[0-9]))?$"
    guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }

    var offset = 0
    for (index, rawLine) in text.components(separatedBy: "\n").enumerated() {
        let rawLength = rawLine.utf16.count
        let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
        if !trimmed.isEmpty && !trimmed.hasPrefix("#") {
            let whole = NSRange(location: 0, length: trimmed.utf16.count)
            if regex.firstMatch(in: trimmed, range: whole) == nil {
                return AllowlistIssue(
                    lineNumber: index + 1,
                    text: trimmed,
                    range: NSRange(location: offset, length: rawLength))
            }
        }
        offset += rawLength + 1  // +1 是被 components 吃掉的那个换行
    }
    return nil
}
