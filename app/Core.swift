import Foundation

// PF 出站防火墙 —— 执行层：查状态（免密）与跑 root 脚本（弹授权框）。
// 规则和脚本正文全在 Rules.swift，这里只负责“把它跑起来”。

enum FirewallError: Error, CustomStringConvertible {
    case cancelled              // 用户在授权框点了取消，静默处理，不弹错误
    case failed(String)

    var description: String {
        switch self {
        case .cancelled: return "已取消"
        case .failed(let message): return message
        }
    }
}

// ============================================================================
// 进程调用
// ============================================================================

/// 跑一个命令，收集退出码和两路输出。
/// 先读完管道再 waitUntilExit：输出超过管道缓冲区时反过来写会死锁。
private func capture(_ launchPath: String, _ arguments: [String]) throws -> (Int32, String, String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: launchPath)
    process.arguments = arguments

    let outPipe = Pipe()
    let errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    try process.run()

    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()

    return (process.terminationStatus,
            String(decoding: outData, as: UTF8.self),
            String(decoding: errData, as: UTF8.self))
}

/// 以管理员身份执行一段 shell 脚本，弹系统授权框。
///
/// 做法：脚本先落到当前用户专属的临时目录（/var/folders/…，权限 0700，
/// 只有本人和 root 能写），再让 osascript 的 “with administrator privileges”
/// 去跑它。脚本路径通过 argv 传给 osascript，不拼进 AppleScript 字面量，
/// 于是只剩 shell 一层引用要管 —— 那一层由 Rules.swift 的 shellQuote 负责。
func runAdmin(_ script: String) throws {
    let scriptURL = FileManager.default.temporaryDirectory
        .appendingPathComponent("pf-outbound-\(UUID().uuidString).sh")
    defer { try? FileManager.default.removeItem(at: scriptURL) }

    do {
        try script.write(to: scriptURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: scriptURL.path)
    } catch {
        throw FirewallError.failed("无法写入临时脚本：\(error.localizedDescription)")
    }

    let (status, _, errorText) = try capture("/usr/bin/osascript", [
        "-e", "on run argv",
        "-e", "do shell script \"/bin/sh \" & quoted form of (item 1 of argv) "
            + "with administrator privileges",
        "-e", "end run",
        scriptURL.path,
    ])
    guard status != 0 else { return }

    // AppleScript 的 -128 是“用户取消”，跟真失败区分开。
    if errorText.contains("-128") { throw FirewallError.cancelled }
    let message = errorText.trimmingCharacters(in: .whitespacesAndNewlines)
    throw FirewallError.failed(message.isEmpty ? "命令执行失败（退出码 \(status)）" : message)
}

// ============================================================================
// 状态查询（都不需要 root）
// ============================================================================

/// 只有开机脚本成功加载过 PF 规则才会有 installed.ok。
/// 上次安装中途失败时这里仍报“未安装”，再点一次安装即可修复。
func isInstalled() -> Bool {
    let manager = FileManager.default
    return manager.fileExists(atPath: Paths.dataDir)
        && manager.fileExists(atPath: Paths.daemonPlist)
        && manager.fileExists(atPath: Paths.installMarker)
}

/// 不查 pfctl —— 那需要 root，普通用户问会因权限不足误报“已关闭”。
/// 默认装完就是开启，只有本程序成功停用后才会写下关闭标记。
func isProtected() -> Bool {
    isInstalled() && !FileManager.default.fileExists(atPath: Paths.disabledMarker)
}

func readAllowlist() -> String {
    (try? String(contentsOfFile: Paths.allowlist, encoding: .utf8)) ?? ""
}

/// 这次安装是不是带 WatchPaths 的新版。
/// 旧版（第一步那版）装好的 LaunchDaemon 没有这个键，也没把白名单设成
/// admin 组可写，免密保存走不通，得重新安装一次才能升级。
func installSupportsWatchPaths() -> Bool {
    guard let text = try? String(contentsOfFile: Paths.daemonPlist, encoding: .utf8) else {
        return false
    }
    return text.contains("<key>WatchPaths</key>")
}

// ============================================================================
// 免密保存
// ============================================================================

/// 守护进程处理完一次变更后写下的结果。
struct ApplyStatus {
    let ok: Bool
    let detail: String
}

private func applyStatusModified() -> Date? {
    let attributes = try? FileManager.default.attributesOfItem(atPath: Paths.applyStatus)
    return attributes?[.modificationDate] as? Date
}

private func readApplyStatus() -> ApplyStatus? {
    guard let text = try? String(contentsOfFile: Paths.applyStatus, encoding: .utf8) else {
        return nil
    }
    var lines = text.components(separatedBy: "\n")
    let verdict = lines.isEmpty ? "" : lines.removeFirst()
    let detail = lines.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
    return ApplyStatus(ok: verdict.hasPrefix("ok"), detail: detail)
}

/// 原地截断重写白名单，不走提权。
///
/// 不用「写临时文件再改名」那套原子写法：那需要目录可写，而目录里放着
/// root 要执行的 startup.sh，不能松权限。所以这里直接截断后一次写完，
/// 守护脚本那边有 0.3 秒的等待来避开写到一半被触发。
private func writeAllowlistDirectly(_ text: String) throws {
    guard let handle = FileHandle(forWritingAtPath: Paths.allowlist) else {
        throw FirewallError.failed("无法写入白名单文件")
    }
    defer { try? handle.close() }
    do {
        try handle.truncate(atOffset: 0)
        try handle.write(contentsOf: Data(text.utf8))
    } catch {
        throw FirewallError.failed("写入白名单失败：\(error.localizedDescription)")
    }
}

/// 免密保存：写文件 → 等 WatchPaths 触发的守护进程回报结果。
///
/// 超时返回 nil，调用方按「已保存，但没等到确认」处理 —— 不要当成失败，
/// 因为文件确实已经写进去了，守护进程只是慢了。
func saveAllowlistWithoutPassword(_ text: String, timeout: TimeInterval = 8) throws -> ApplyStatus? {
    let before = applyStatusModified()
    try writeAllowlistDirectly(text)

    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        Thread.sleep(forTimeInterval: 0.1)
        let now = applyStatusModified()
        // 首次运行时 before 是 nil，文件一出现就算处理过了。
        if let now, before == nil || now != before {
            return readApplyStatus()
        }
    }
    return nil
}

// ============================================================================
// 操作
// ============================================================================

func installAndEnable() throws {
    try runAdmin(installScript())
}

func saveAllowlist(_ listText: String, apply: Bool) throws {
    try runAdmin(saveScript(listText: listText, apply: apply))
}

func uninstallFirewall() throws {
    try runAdmin(uninstallScript())
}

func disableProtection() throws {
    try runAdmin(disableScript())
}

/// 开启防护前先把当前编辑框内容落盘（但不加载），再一次性加载并启用。
///
/// 新版安装下白名单可以免密写，于是只剩启用这一步要密码；
/// 旧版安装退回到「保存+启用」合成一个提权脚本，同样只输一次。
func enableProtection(listText: String) throws {
    let wroteWithoutPassword = installSupportsWatchPaths()
        && (try? writeAllowlistDirectly(listText)) != nil
    if wroteWithoutPassword {
        try runAdmin(enableScript())
    } else {
        try runAdmin(saveScript(listText: listText, apply: false) + enableScript())
    }
}
