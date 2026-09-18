import Foundation

// Rules.swift 的测试。不依赖 XCTest 和 Xcode 工程：
// ./test.sh 把 app/Rules.swift 和本文件一起 swiftc 成一个可执行文件跑掉。
// 不需要装 App，也不需要 root。

var failures = 0
var checks = 0

func check(_ condition: Bool, _ name: String) {
    checks += 1
    if !condition {
        failures += 1
        print("❌ \(name)")
    }
}

func checkEqual(_ actual: String, _ expected: String, _ name: String) {
    checks += 1
    if actual != expected {
        failures += 1
        print("❌ \(name)\n   实际: \(actual)\n   期望: \(expected)")
    }
}

// ============================================================================
// shellQuote
// ============================================================================
func testShellQuote() {
    checkEqual(shellQuote("8.8.8.8"), "'8.8.8.8'", "普通文本加单引号")
    checkEqual(shellQuote("/Library/Application Support/X"),
               "'/Library/Application Support/X'", "空格无需额外处理")
    checkEqual(shellQuote("a'b"), "'a'\\''b'", "内嵌单引号被转义")
    checkEqual(shellQuote(""), "''", "空字符串")

    // 关键：这些内容会被 root 执行的脚本引用，任何一种逃逸都是提权。
    for payload in ["'; rm -rf /; echo '",
                    "$(rm -rf /)",
                    "`rm -rf /`",
                    "a\nrm -rf /\n",
                    "\\'; touch /tmp/pwned; '"] {
        let quoted = shellQuote(payload)
        check(quoted.hasPrefix("'") && quoted.hasSuffix("'"), "注入载荷仍被整体包裹")
        // 去掉首尾引号后，内部不能再出现裸单引号
        let inner = String(quoted.dropFirst().dropLast())
        check(!inner.contains("'") || inner.contains("'\\''"),
              "注入载荷内的单引号已转义: \(payload)")
    }
}

// ============================================================================
// PF 规则
// ============================================================================
func testPFRules() {
    let rules = pfRules(allowlistPath: "/tmp/list.txt")
    check(rules.contains("table <vpn_allowlist> persist file \"/tmp/list.txt\""), "表指向给定路径")
    // 回环必须 set skip 整个跳过，用 pass 规则会因为状态跟踪把本机 TCP 服务
    // 全部打死（出站 SYN 建状态，同一个 SYN 从 lo0 入站时被判为序列异常丢弃）。
    check(rules.contains("set skip on lo0"), "回环走 set skip")
    check(!rules.contains("pass out quick on lo0"), "回环不能用 pass 规则")
    // set 属于选项，必须排在过滤规则前面，否则 pfctl 直接语法错误。
    guard let skipAt = rules.range(of: "set skip"),
          let firstRule = rules.range(of: "pass out quick") else {
        check(false, "规则缺少 set skip 或 pass 规则")
        return
    }
    check(skipAt.lowerBound < firstRule.lowerBound, "set skip 排在过滤规则之前")
    // 必须枚举，不能用通配：macOS 的 pf 收 utun* 的语法但运行时一个包都不匹配
    // （实测 on utun* 评估 1921 次命中 0 包，同期 on utun4 命中 1422 包）。
    check(!rules.contains("utun*"), "绝不能用 utun* 通配")
    check(!rules.contains("on utun all"), "也不能用接口组写法")
    for index in 0...maxUtunIndex {
        check(rules.contains("utun\(index)"), "放行 utun\(index)")
    }
    check(!rules.contains("utun\(maxUtunIndex + 1)"), "上限之外不放行")
    check(rules.contains("pass out quick to <vpn_allowlist>"), "放行白名单")
    // 规则不指定地址族，IPv4/IPv6 都走同一套。
    check(!rules.contains("inet6"), "不按地址族分叉")
    check(!rules.contains("inet "), "不按地址族分叉")

    // 兜底的 block 必须是最后一条：pf 的 quick 先匹配先生效，
    // 它要是跑到前面去，整条规则集就等于全断网。
    let lines = rules.split(separator: "\n")
    checkEqual(String(lines.last ?? ""), "block drop out quick all", "block 是最后一条")
    check(rules.hasSuffix("\n"), "规则文件以换行结尾")
}

func testPFLoadCommand() {
    let command = pfLoadCommand(rulesPath: "/tmp/rules.conf")
    check(command.contains("/sbin/pfctl -f '/tmp/rules.conf'"), "加载给定规则文件")
    check(command.contains("-ge 10"), "重试上限 10 次")
    check(command.contains("/bin/sleep 0.2"), "重试间隔 0.2 秒")
}

// ============================================================================
// root 脚本
// ============================================================================
func testSaveScript() {
    let script = saveScript(listText: "8.8.8.8\n", apply: true)

    // 先 -nf 干跑校验、再 mv 覆盖正式文件，顺序错了就可能把自己锁死。
    guard let validateAt = script.range(of: "pfctl -nf"),
          let moveAt = script.range(of: "/bin/mv") else {
        check(false, "保存脚本缺少校验或覆盖步骤")
        return
    }
    check(validateAt.lowerBound < moveAt.lowerBound, "先干跑校验再覆盖正式文件")
    check(script.contains("set -e"), "任一步失败立即中止")
    check(script.contains("/sbin/pfctl -F states"), "apply=true 时清空连接状态")

    let noApply = saveScript(listText: "8.8.8.8\n", apply: false)
    check(!noApply.contains("pfctl -F states"), "apply=false 时不动内核状态")
    check(!noApply.contains("pfctl -f "), "apply=false 时不加载规则")

    // 白名单正文是用户输入，必须原样躺在单引号里。
    let hostile = saveScript(listText: "1.1.1.1'; touch /tmp/pwned; echo '", apply: false)
    check(!hostile.contains("; touch /tmp/pwned; echo \n"), "恶意白名单没有逃出引号")
    check(hostile.contains("'\\''"), "恶意白名单里的单引号被转义")
}

func testInstallScript() {
    let script = installScript()
    check(script.contains("launchctl bootstrap system"), "装 LaunchDaemon")
    check(script.contains("launchctl bootout system/\(Paths.serviceID)"), "先清掉旧服务")
    check(script.contains("bootout") && script.contains("|| true"), "旧服务不存在也不算失败")
    check(script.contains("-lt 100"), "最多等 10 秒（100 × 0.1s）")
    check(script.contains("/bin/cat '\(Paths.startupLog)' >&2"), "失败时输出开机日志")
    // 白名单要 admin 组可写，GUI 才能免密改它。
    check(script.contains("/usr/sbin/chown root:admin '\(Paths.allowlist)'"), "白名单归 admin 组")
    check(script.contains("/bin/chmod 664 '\(Paths.allowlist)'"), "白名单组可写")
    // 目录不能放权：root 执行的 startup.sh 就在里面。
    check(script.contains("/bin/chmod 755 '\(Paths.dataDir)'"), "目录仍只有 root 可写")
    check(!script.contains("chmod 775 '\(Paths.dataDir)'"), "目录没有被设成组可写")

    // bootstrap 的 RunAtLoad 已经会加载 PF，安装脚本不能自己再并发加载一次
    // （两个 pfctl -f 撞在一起就是 DIOCXCOMMIT: Resource busy）。
    // 脚本里唯一一处加载命令，应该是被 printf 写进 startup.sh 的那份数据。
    check(daemonScript().contains("/sbin/pfctl -f"), "守护脚本负责加载 PF")
    // 开机脚本整体是被单引号裹起来当数据写进去的（路径里的引号会被再转义，
    // 所以不能直接 contains(pfLoadCommand())，要比对转义后的形态）。
    check(script.contains(shellQuote(daemonScript())), "守护脚本作为数据整体嵌入")
    let occurrences = script.components(separatedBy: "until /sbin/pfctl -f").count - 1
    check(occurrences == 1, "加载命令只出现一次，即嵌入的那份（实际 \(occurrences) 次）")
}

func testUninstallScript() {
    let script = uninstallScript()
    check(script.contains("launchctl bootout"), "停服务")
    check(script.contains("/sbin/pfctl -d"), "关闭 PF")
    check(script.contains("/bin/rm -rf '\(Paths.dataDir)'"), "删配置目录")
    check(script.contains("/bin/rm -f '\(Paths.daemonPlist)'"), "删 LaunchDaemon")
    // 半装状态也要能卸干净，所以每步都得容错。
    check(!script.contains("set -e"), "卸载不用 set -e")
}

func testToggleScripts() {
    let disable = disableScript()
    check(disable.contains("/usr/bin/touch '\(Paths.disabledMarker)'"), "写下关闭标记")
    check(disable.contains("pfctl -F states"), "关闭时清空连接状态")

    let enable = enableScript()
    check(enable.contains("/bin/rm -f '\(Paths.disabledMarker)'"), "清掉关闭标记")
    check(enable.contains("pfctl -e"), "必要时启用 PF")
    check(enable.contains("pfctl -F states"), "启用时清空关闭期间建立的直连")
}

// ============================================================================
// 守护脚本与 WatchPaths
// ============================================================================
func testDaemonPlist() {
    let plist = daemonPlist()
    check(plist.contains("<key>WatchPaths</key>"), "带 WatchPaths")
    check(plist.contains("<string>\(Paths.allowlist)</string>"), "监视白名单文件")
    check(plist.contains("<key>RunAtLoad</key>"), "开机仍然自启")
    // launchd 默认两次启动间隔 10 秒，不调小的话连着改白名单会卡很久。
    check(plist.contains("<key>ThrottleInterval</key><integer>1</integer>"), "节流调到 1 秒")
}

func testDaemonScriptNeverWritesAllowlist() {
    // 这是整个 WatchPaths 方案最致命的坑：守护脚本只要碰一下白名单，
    // 就会把自己再次触发，无限循环烧 CPU。
    let script = daemonScript()
    let allowlist = shellQuote(Paths.allowlist)
    for redirect in ["> \(allowlist)", ">> \(allowlist)",
                     "touch \(allowlist)", "mv \(allowlist)", "tee \(allowlist)"] {
        check(!script.contains(redirect), "守护脚本不写白名单: \(redirect)")
    }
    // 只读它是可以的 —— 实际上连读都不用，pfctl 自己去读 table 文件。
    check(script.contains(shellQuote(Paths.rules)), "守护脚本加载的是 rules.conf")
}

func testDaemonFastPath() {
    let script = daemonScript()
    // 白名单变更走 -T replace：只换内核里那张表，不重载规则集、不清状态，
    // 现有连接一条都不会断。
    check(script.contains("-T replace -f '\(Paths.allowlist)'"), "快路径用 -T replace 换表")

    // 走快路径的前提：pf 已启用、表已存在、内核里就是当前这份 rules.conf。
    check(script.contains("md5 -q"), "用校验和判断规则集有没有变")
    check(script.contains("'\(Paths.loadedRulesHash)'"), "比对上次加载的校验和")
    check(script.contains("-T show"), "取表内容做前后对比")

    // 删条目时光换表不够，已建立的连接靠旧状态还能跑，必须清状态。
    guard let removedCheck = script.range(of: "if [ -n \"$removed\" ]"),
          let flush = script.range(of: "/sbin/pfctl -F states", range: removedCheck.upperBound..<script.endIndex) else {
        check(false, "删条目后缺少清状态")
        return
    }
    check(flush.lowerBound > removedCheck.lowerBound, "仅在有条目被移除时清状态")

    // 全量路径跑完要记下校验和，否则下次永远走不了快路径。
    check(script.contains("> '\(Paths.loadedRulesHash)'"), "全量加载后记录校验和")
    // 两条路径都要落 installed.ok，安装脚本靠它判断装好没有。
    let markerCount = script.components(separatedBy: "touch '\(Paths.installMarker)'").count - 1
    check(markerCount == 2, "快慢两条路径都写 installed.ok（实际 \(markerCount) 处）")
}

func testInstallResetsRulesHash() {
    // 装完第一次必须走全量加载，不能因为哈希碰巧相同就跳过。
    check(installScript().contains("/bin/rm -f '\(Paths.loadedRulesHash)'"), "安装时清掉旧校验和")
}

func testDaemonScriptReportsEveryPath() {
    let script = daemonScript()
    // 每条退出路径都要写状态，否则 GUI 只能干等到超时。
    check(script.contains("report fail \"白名单语法有误"), "语法错误要回报")
    check(script.contains("report fail \"加载 PF 规则失败"), "加载失败要回报")
    check(script.contains("report ok \"防护当前已关闭"), "已关闭状态要回报")
    check(script.contains("report ok \"已生效"), "成功要回报")

    // 用户主动关掉防护后，改白名单不应该把防护偷偷打开。
    guard let disabledCheck = script.range(of: "if [ -f \(shellQuote(Paths.disabledMarker)) ]"),
          let enable = script.range(of: "/sbin/pfctl -e") else {
        check(false, "守护脚本缺少关闭标记判断或启用步骤")
        return
    }
    check(disabledCheck.lowerBound < enable.lowerBound, "先判断关闭标记再谈启用")
    check(script.contains("/bin/sleep 0.3"), "等待写入落定，避开写到一半被触发")
}

// ============================================================================
// 白名单校验
// ============================================================================
func testAllowlistAccepts() {
    let valid = [
        "", "\n", "   \n\t\n",
        "8.8.8.8",
        "0.0.0.0",
        "255.255.255.255",
        "192.168.1.0/24",
        "10.0.0.0/8",
        "1.2.3.4/32",
        "1.2.3.4/0",
        "  8.8.8.8  ",                    // 前后空白应被忽略
        "# 注释",
        "  # 缩进的注释",
        "8.8.8.8\n# 节点\n203.0.113.10\n192.168.0.0/16\n",
        // IPv6
        "2001:4860:4860::8888",
        "2606:4700::/32",
        "::1",
        "::",
        "fe80::1",
        "2001:db8:85a3:0:0:8a2e:370:7334",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "::ffff:192.168.1.1",              // IPv4 映射地址
        "2001:db8::/128",
        "2001:db8::/0",
        "  2001:db8::1  ",
        "fe80::1%en0",                     // 带 scope 的链路本地地址，pf 也收
        "8.8.8.8\n2001:4860:4860::8888\n# 混排\n10.0.0.0/8\n2606:4700::/32\n",
    ]
    for text in valid {
        check(validateAllowlist(text) == nil, "应接受: \(text.debugDescription)")
    }
}

func testAllowlistRejects() {
    let invalid = [
        "256.1.1.1",          // 超出 255
        // pf 走 inet_aton 会把这些当简写收下（1.2.3 → 1.2.0.3），含义与直觉相反，
        // 我们走 inet_pton 一律拒绝。见 tests/cross-check-pf.sh
        "1.2.3",
        "1.2",
        "16909060",
        "1.2.3.4.5",          // 段数过多
        "1.2.3.4/33",         // 掩码越界
        "1.2.3.4/",           // 掩码缺失
        "example.com",        // 不支持域名
        "1.2.3.4 5.6.7.8",    // 一行只能一条
        // IPv6 的错法
        "2001:db8::1/129",    // 前缀越界
        "2001:xyz::1",        // 非法字符
        "2001:db8:::1",       // 三个冒号
        "2001:db8::1::2",     // 两处压缩
        "2001:db8::1/",       // 前缀缺失
        "2001:db8::1/-1",
        "12345::1",           // 段超过 4 位
        "01.2.3.4",           // 前导零：pf 收，但换个工具可能按八进制读
        "010.1.1.1",
        "1.2.3.04",
        "-1.2.3.4",
    ]
    for text in invalid {
        check(validateAllowlist(text) != nil, "应拒绝: \(text.debugDescription)")
    }
}

func testPrefixLengthBounds() {
    // v4 上限 32、v6 上限 128，别用同一个数
    check(isValidAllowlistEntry("1.2.3.4/32"), "v4 /32 合法")
    check(!isValidAllowlistEntry("1.2.3.4/33"), "v4 /33 越界")
    check(!isValidAllowlistEntry("1.2.3.4/128"), "v4 不能用 v6 的上限")
    check(isValidAllowlistEntry("2001:db8::/128"), "v6 /128 合法")
    check(!isValidAllowlistEntry("2001:db8::/129"), "v6 /129 越界")
    check(isValidAllowlistEntry("2001:db8::/33"), "v6 /33 合法")
}

func testAllowlistIssueLocation() {
    let text = "8.8.8.8\n# 注释\n999.1.1.1\n1.1.1.1"
    guard let issue = validateAllowlist(text) else {
        check(false, "应报出第 3 行有误")
        return
    }
    check(issue.lineNumber == 3, "行号为 3，实际 \(issue.lineNumber)")
    checkEqual(issue.text, "999.1.1.1", "报出出错内容")

    // range 要能直接喂给 NSTextView 选中，按 UTF-16 计长。
    let nsText = text as NSString
    checkEqual(nsText.substring(with: issue.range), "999.1.1.1", "range 正好圈住那一行")
}

func testAllowlistRangeWithCJK() {
    // 注释里的中文占 UTF-16 一个码元、Character 也算一个，但换算一旦写错
    // 偏移就会漂掉，所以专门验一条带中文和 emoji 的。
    let text = "# 香港节点 🇭🇰\n1.1.1.1\n坏行"
    guard let issue = validateAllowlist(text) else {
        check(false, "应报出第 3 行有误")
        return
    }
    check(issue.lineNumber == 3, "中文注释后行号仍为 3，实际 \(issue.lineNumber)")
    let nsText = text as NSString
    checkEqual(nsText.substring(with: issue.range), "坏行", "中文/emoji 后 range 未漂移")
}

// ============================================================================
@main
enum RulesTests {
    static func main() {
        testShellQuote()
        testPFRules()
        testPFLoadCommand()
        testSaveScript()
        testInstallScript()
        testUninstallScript()
        testToggleScripts()
        testDaemonPlist()
        testDaemonScriptNeverWritesAllowlist()
        testDaemonScriptReportsEveryPath()
        testDaemonFastPath()
        testInstallResetsRulesHash()
        testAllowlistAccepts()
        testAllowlistRejects()
        testPrefixLengthBounds()
        testAllowlistIssueLocation()
        testAllowlistRangeWithCJK()

        if failures == 0 {
            print("✅ \(checks) 项全部通过")
        } else {
            print("❌ \(failures)/\(checks) 项失败")
            exit(1)
        }
    }
}
