import Foundation

// 当前出站连接的采集与归类。
//
// pf 工作在数据包层，内核里没有「进程」这个概念，所以规则命中计数只能告诉你
// 有多少包被挡了，给不出是谁发的。想把连接对应到应用，只能在用户态拿 lsof
// 的快照去凑 —— 尽力而为：短命连接可能在两次采样之间就结束了。
//
// 真正按应用逐流放行/拒绝要用 NetworkExtension 的 NEFilterDataProvider，
// 那需要付费开发者账号的 networkextension 权限和系统扩展，是另一套架构。
//
// 本文件只依赖 Foundation，纯解析函数可以直接进测试。

// ============================================================================
// 连接
// ============================================================================
struct Connection: Identifiable, Hashable {
    let processName: String
    let pid: Int32
    let netProtocol: String        // TCP / UDP
    let localAddress: String
    let localPort: String
    let remoteAddress: String
    let remotePort: String

    /// 本地端口必须算进来：同一个进程往同一个目标开多条 socket 很常见
    /// （cloudd 就是），漏掉的话多行会撞同一个 id，SwiftUI 的列表会错乱。
    var id: String {
        "\(pid)|\(netProtocol)|\(localAddress):\(localPort)|\(remoteAddress):\(remotePort)"
    }

    var remoteDisplay: String {
        remotePort.isEmpty ? remoteAddress : "\(remoteAddress):\(remotePort)"
    }
}

/// 这条连接在当前规则下会怎样。
enum ConnectionVerdict {
    case tunnel        // 从 utun 出去，被 pass on utunN 放行
    case allowlisted   // 物理网卡直连，但目标命中地址表
    case loopback      // 本机回环，set skip 完全不过 pf
    case blocked       // 物理网卡直连且不在表里 —— 开着防护就会被丢掉

    var label: String {
        switch self {
        case .tunnel: return "走隧道"
        case .allowlisted: return "白名单直连"
        case .loopback: return "本机"
        case .blocked: return "会被阻断"
        }
    }
}

// ============================================================================
// lsof 解析
// ============================================================================

/// 解析 `lsof -nP -i -F pcnPT` 的字段输出。
///
/// 格式是按行的「字段字母 + 值」，p 开一个进程块，f 开一个文件块，
/// 后续 P/n/T 属于当前文件。只保留 n 里带 `->` 的，也就是真有对端的连接；
/// 监听套接字（`*:443`）不算连接。
func parseLsofOutput(_ output: String) -> [Connection] {
    var result: [Connection] = []
    var pid: Int32 = 0
    var command = ""
    var netProtocol = ""
    var name = ""

    func flush() {
        defer { netProtocol = ""; name = "" }
        guard let arrow = name.range(of: "->") else { return }
        let localPart = String(name[name.startIndex..<arrow.lowerBound])
        let remotePart = String(name[arrow.upperBound...])
        guard let local = splitHostPort(localPart),
              let remote = splitHostPort(remotePart) else { return }
        result.append(Connection(processName: command,
                                 pid: pid,
                                 netProtocol: netProtocol.isEmpty ? "TCP" : netProtocol,
                                 localAddress: local.host,
                                 localPort: local.port,
                                 remoteAddress: remote.host,
                                 remotePort: remote.port))
    }

    for line in output.components(separatedBy: "\n") {
        guard let marker = line.first else { continue }
        let value = String(line.dropFirst())
        switch marker {
        case "p":
            flush()
            pid = Int32(value) ?? 0
        case "c":
            flush()
            command = value
        case "f":
            flush()        // 上一个文件块到此结束
        case "P":
            netProtocol = value
        case "n":
            name = value
        default:
            break          // T（状态）、TQR/TQS（队列长度）等用不上
        }
    }
    flush()
    return result
}

/// 拆 `1.2.3.4:443` 或 `[fe80::1]:443`。lsof 的 IPv6 带方括号。
func splitHostPort(_ text: String) -> (host: String, port: String)? {
    let trimmed = text.trimmingCharacters(in: .whitespaces)
    guard !trimmed.isEmpty else { return nil }

    if trimmed.hasPrefix("["), let close = trimmed.firstIndex(of: "]") {
        let host = String(trimmed[trimmed.index(after: trimmed.startIndex)..<close])
        let rest = trimmed[trimmed.index(after: close)...]
        return (host, rest.hasPrefix(":") ? String(rest.dropFirst()) : "")
    }
    guard let colon = trimmed.lastIndex(of: ":") else { return (trimmed, "") }
    return (String(trimmed[trimmed.startIndex..<colon]),
            String(trimmed[trimmed.index(after: colon)...]))
}

// ============================================================================
// 地址匹配
// ============================================================================

/// 把地址转成字节，顺带给出地址族。认不出来返回 nil。
private func addressBytes(_ text: String) -> (bytes: [UInt8], family: Int32)? {
    var v4 = in_addr()
    if text.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
        return (withUnsafeBytes(of: v4.s_addr) { Array($0) }, AF_INET)
    }
    var v6 = in6_addr()
    if text.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
        return (withUnsafeBytes(of: v6) { Array($0) }, AF_INET6)
    }
    return nil
}

/// 地址是否落在某条白名单记录里。entry 可以是单个地址，也可以是 `地址/前缀`。
///
/// 自己按位比，不调 pf —— 界面要对几十条连接逐条判断，
/// 每次都去 shell 一趟 pfctl 太慢，而且防护关着的时候内核里压根没有表。
func addressMatches(_ address: String, entry: String) -> Bool {
    let parts = entry.components(separatedBy: "/")
    guard let target = addressBytes(address),
          let network = addressBytes(parts[0]),
          target.family == network.family else { return false }

    let fullBits = network.bytes.count * 8
    var prefix = fullBits
    if parts.count == 2 {
        guard let value = Int(parts[1]), value >= 0, value <= fullBits else { return false }
        prefix = value
    }
    if prefix == 0 { return true }

    let wholeBytes = prefix / 8
    if wholeBytes > 0,
       Array(target.bytes[0..<wholeBytes]) != Array(network.bytes[0..<wholeBytes]) {
        return false
    }
    let remainingBits = prefix % 8
    if remainingBits > 0 {
        // 移位必须在 UInt8 域里做：写成 UInt8(0xFF << (8 - bits)) 会先在 Int 里
        // 算出 0x1FE0 之类再转换，直接溢出崩溃。
        let mask = UInt8(0xFF) << UInt8(8 - remainingBits)
        if target.bytes[wholeBytes] & mask != network.bytes[wholeBytes] & mask { return false }
    }
    return true
}

// ============================================================================
// 聚合
// ============================================================================

/// 同一个进程到同一个目标的多条 socket 合成一行，附带条数。
/// cloudd 之类的进程一开就是十几条到同一地址，逐条列出来没法看。
struct ConnectionGroup: Identifiable {
    let sample: Connection
    let count: Int

    var id: String {
        "\(sample.processName)|\(sample.netProtocol)|\(sample.remoteAddress):\(sample.remotePort)"
    }
}

func groupConnections(_ list: [Connection]) -> [ConnectionGroup] {
    var order: [String] = []
    var buckets: [String: (Connection, Int)] = [:]
    for connection in list {
        let key = "\(connection.processName)|\(connection.netProtocol)"
            + "|\(connection.remoteAddress):\(connection.remotePort)"
        if let existing = buckets[key] {
            buckets[key] = (existing.0, existing.1 + 1)
        } else {
            buckets[key] = (connection, 1)
            order.append(key)
        }
    }
    return order.compactMap { key in
        buckets[key].map { ConnectionGroup(sample: $0.0, count: $0.1) }
    }
}

func addressIsAllowlisted(_ address: String, entries: [String]) -> Bool {
    entries.contains { addressMatches(address, entry: $0) }
}

// ============================================================================
// 归类
// ============================================================================

func classify(_ connection: Connection,
              tunnelAddresses: Set<String>,
              allowEntries: [String]) -> ConnectionVerdict {
    if connection.localAddress.hasPrefix("127.")
        || connection.localAddress == "::1"
        || connection.remoteAddress.hasPrefix("127.")
        || connection.remoteAddress == "::1" {
        return .loopback
    }
    // 本地地址就是某个 utun 的地址 —— 这条连接确确实实是从隧道出去的，
    // 比查路由表更直接，也不受路由变化影响。
    if tunnelAddresses.contains(connection.localAddress) {
        return .tunnel
    }
    if addressIsAllowlisted(connection.remoteAddress, entries: allowEntries) {
        return .allowlisted
    }
    return .blocked
}

// ============================================================================
// 采集
// ============================================================================

/// 所有 utun 接口当前的地址。
func tunnelAddresses() -> Set<String> {
    guard let output = try? runTool("/sbin/ifconfig", ["-a"]) else { return [] }
    var result: Set<String> = []
    var insideTunnel = false
    for line in output.components(separatedBy: "\n") {
        if !line.hasPrefix("\t") && !line.hasPrefix(" ") {
            insideTunnel = line.hasPrefix("utun")
            continue
        }
        guard insideTunnel else { continue }
        // 必须按「空格和制表符」一起切：ifconfig 的地址行以 \t 开头，
        // 只切空格的话第一个 token 会是 "\tinet"，永远匹配不上。
        let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        if let index = fields.firstIndex(where: { $0 == "inet" || $0 == "inet6" }),
           index + 1 < fields.count {
            // IPv6 可能带 %en0 之类的 scope，去掉再存
            result.insert(fields[index + 1].components(separatedBy: "%")[0])
        }
    }
    return result
}

/// pf 实际使用的那份地址表。守护脚本把它写成 644，所以不用提权就能读。
func effectiveEntries() -> [String] {
    let path = FileManager.default.fileExists(atPath: Paths.effectiveList)
        ? Paths.effectiveList : Paths.allowlist
    guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
    return text.components(separatedBy: "\n")
        .map { $0.trimmingCharacters(in: .whitespaces) }
        .filter { !$0.isEmpty && !$0.hasPrefix("#") }
}

/// 采一次当前连接快照。
///
/// 不提权的 lsof 只看得到当前用户的进程，系统守护进程（root 跑的那些）看不到。
/// 这是 v1 的已知限制，界面上有说明。
func collectConnections() -> [Connection] {
    guard let output = try? runTool("/usr/sbin/lsof", ["-nP", "-i", "-F", "pcnPT"]) else {
        return []
    }
    return parseLsofOutput(output)
}

private func runTool(_ path: String, _ arguments: [String]) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = arguments
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = FileHandle.nullDevice
    try process.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return String(decoding: data, as: UTF8.self)
}
