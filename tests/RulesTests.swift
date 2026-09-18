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
    let script = uninstallScript(keepConfig: false)
    check(script.contains("launchctl bootout"), "停服务")
    check(script.contains("/sbin/pfctl -d"), "关闭 PF")
    check(script.contains("/bin/rm -rf '\(Paths.dataDir)'"), "删配置目录")
    check(script.contains("/bin/rm -f '\(Paths.daemonPlist)'"), "删 LaunchDaemon")
    // 半装状态也要能卸干净，所以每步都得容错。
    check(!script.contains("set -e"), "卸载不用 set -e")

    // 保留配置时白名单不能被删 —— 那是用户一条条试出来的，删了代价很高。
    let keep = uninstallScript(keepConfig: true)
    check(!keep.contains("rm -rf '\(Paths.dataDir)'"), "保留模式不删整个目录")
    check(!keep.contains("rm -f '\(Paths.allowlist)'"), "保留模式不删白名单")
    check(keep.contains("launchctl bootout"), "保留模式同样停服务")
    check(keep.contains("/sbin/pfctl -d"), "保留模式同样关闭 PF")
    check(keep.contains("rm -f '\(Paths.daemonPlist)'"), "保留模式同样移除开机自启")
    // 运行期文件要清掉，否则下次安装会带着上次的残留状态
    for path in [Paths.rules, Paths.startup, Paths.installMarker, Paths.loadedRulesHash] {
        check(keep.contains("rm -f '\(path)'"), "保留模式仍清理 \(path)")
    }
    // 彻底删除模式必须真的删干净
    check(script.contains("rm -rf '\(Paths.dataDir)'"), "彻底模式删整个目录")
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
    check(script.contains("-T replace -f '\(Paths.effectiveList)'"), "快路径用 -T replace 换表")

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
// 高级选项
// ============================================================================
func testFirewallOptions() {
    // 默认全开
    let d = FirewallOptions()
    check(d.allowLAN && d.allowDHCP, "默认两项都开")
    check(d.builtinEntries.contains("10.0.0.0/8"), "默认含私有网段")
    check(d.builtinEntries.contains("255.255.255.255"), "默认含 DHCP 广播")

    // 关掉之后对应条目要消失
    var off = FirewallOptions(); off.allowLAN = false; off.allowDHCP = false
    check(off.builtinEntries.isEmpty, "全关则没有内置条目")
    var lanOnly = FirewallOptions(); lanOnly.allowDHCP = false
    check(!lanOnly.builtinEntries.contains("255.255.255.255"), "关 DHCP 后不含广播地址")
    check(lanOnly.builtinEntries.contains("192.168.0.0/16"), "关 DHCP 不影响局域网")

    // 序列化往返
    for original in [FirewallOptions(), off, lanOnly] {
        let parsed = FirewallOptions.parse(original.serialized())
        check(parsed == original, "序列化往返一致")
    }

    // 缺键、乱码时宁可多放行，也不要突然把用户局域网掐了
    check(FirewallOptions.parse("") == FirewallOptions(), "空文件按默认（全开）")
    check(FirewallOptions.parse("垃圾内容\n???") == FirewallOptions(), "无法解析按默认")
    check(FirewallOptions.parse("lan=0").allowDHCP, "只写了 lan，dhcp 仍按默认开")
    check(!FirewallOptions.parse("lan=0").allowLAN, "lan=0 生效")
    check(FirewallOptions.parse("lan = 1").allowLAN, "容忍等号两边空格")

    // 内置条目本身必须是合法地址，否则会让整条规则集加载失败
    for entry in FirewallOptions().builtinEntries {
        check(isValidAllowlistEntry(entry), "内置条目 \(entry) 合法")
    }
}

func testDaemonComposesEffectiveList() {
    let script = daemonScript()
    // pf 读的是合成表，不是用户白名单
    check(pfRules().contains("persist file \"\(Paths.effectiveList)\""), "规则表指向合成表")
    check(script.contains("-T replace -f '\(Paths.effectiveList)'"), "快路径也用合成表")
    // 合成 = 内置条目（按开关）+ 用户白名单
    check(script.contains("opt lan"), "读局域网开关")
    check(script.contains("opt dhcp"), "读 DHCP 开关")
    check(script.contains("/bin/cat '\(Paths.allowlist)' >> "), "拼接用户白名单")
    // 合成表由守护脚本生成，绝不能被 WatchPaths 监视，否则自触发死循环
    check(daemonPlist().contains("<string>\(Paths.options)</string>"), "监视选项文件")
    check(!daemonPlist().contains("<string>\(Paths.effectiveList)</string>"), "不监视合成表")
    // 安装时建选项文件且组可写
    let install = installScript()
    check(install.contains("chown root:admin '\(Paths.options)'"), "选项文件归 admin 组")
    check(install.contains("chmod 664 '\(Paths.options)'"), "选项文件组可写")
    check(install.contains("test -f '\(Paths.options)' ||"), "已存在则不覆盖用户选择")
}

func testPreflightPublicEntryDetection() {
    // 只有私有网段 → 开防护会断网，要拦
    check(!allowlistHasPublicEntry(""), "空白名单没有公网地址")
    check(!allowlistHasPublicEntry("10.0.0.0/8\n192.168.1.1\n172.16.0.0/12"), "全私有网段")
    check(!allowlistHasPublicEntry("# 8.8.8.8\n"), "注释掉的不算")
    check(!allowlistHasPublicEntry("127.0.0.1\n255.255.255.255\n169.254.1.1"), "回环/广播/链路本地都不算")
    // 有公网地址 → 放行
    check(allowlistHasPublicEntry("203.0.113.10"), "VPN 节点算公网")
    check(allowlistHasPublicEntry("10.0.0.0/8\n8.8.8.8"), "混合里有公网")
    check(allowlistHasPublicEntry("172.32.0.1"), "172.32 不在私有段内")
    check(allowlistHasPublicEntry("2606:4700::/32"), "IPv6 算公网")
}

// ============================================================================
// 连接采集
// ============================================================================
func testLsofParsing() {
    // 真实 lsof -F pcnPT 的输出形态：p 开进程块，f 开文件块，P/n/T 属于当前文件
    let sample = """
    p462
    crapportd
    f10
    PTCP
    n*:61447
    TST=LISTEN
    f11
    PTCP
    n192.168.1.68:52000->203.0.113.10:443
    TST=ESTABLISHED
    p1234
    cSafari
    f5
    PTCP
    n[2001:db8::1]:51000->[2606:4700::1111]:443
    TST=ESTABLISHED
    f6
    PUDP
    n198.51.100.2:53888->8.8.8.8:53
    """
    let connections = parseLsofOutput(sample)
    // 监听套接字没有对端，不该被当成连接
    check(connections.count == 3, "解析出 3 条连接（实际 \(connections.count)）")
    guard connections.count == 3 else { return }

    checkEqual(connections[0].processName, "rapportd", "进程名跟着 p 块走")
    check(connections[0].pid == 462, "pid 正确")
    checkEqual(connections[0].remoteAddress, "203.0.113.10", "对端地址")
    checkEqual(connections[0].remotePort, "443", "对端端口")
    checkEqual(connections[0].localAddress, "192.168.1.68", "本地地址")
    checkEqual(connections[0].localPort, "52000", "本地端口")

    // IPv6 在 lsof 里带方括号，要剥掉
    checkEqual(connections[1].processName, "Safari", "第二个进程块")
    checkEqual(connections[1].remoteAddress, "2606:4700::1111", "IPv6 对端去掉方括号")
    checkEqual(connections[1].localAddress, "2001:db8::1", "IPv6 本地去掉方括号")

    checkEqual(connections[2].netProtocol, "UDP", "协议跟着 P 字段")
    checkEqual(connections[2].remoteAddress, "8.8.8.8", "UDP 对端")

    check(parseLsofOutput("").isEmpty, "空输入不崩")
    check(parseLsofOutput("p1\ncFoo\nf1\nn*:80").isEmpty, "只有监听套接字则无连接")
}

func testSplitHostPort() {
    check(splitHostPort("1.2.3.4:443")?.host == "1.2.3.4", "IPv4 主机")
    check(splitHostPort("1.2.3.4:443")?.port == "443", "IPv4 端口")
    check(splitHostPort("[::1]:8080")?.host == "::1", "IPv6 去方括号")
    check(splitHostPort("[::1]:8080")?.port == "8080", "IPv6 端口")
    check(splitHostPort("[fe80::1]")?.port == "", "IPv6 无端口")
    check(splitHostPort("") == nil, "空串返回 nil")
}

func testAddressMatching() {
    // 单个地址
    check(addressMatches("8.8.8.8", entry: "8.8.8.8"), "精确匹配")
    check(!addressMatches("8.8.8.9", entry: "8.8.8.8"), "不同地址不匹配")
    // CIDR：按位比，边界要准
    check(addressMatches("10.1.2.3", entry: "10.0.0.0/8"), "10/8 命中")
    check(!addressMatches("11.1.2.3", entry: "10.0.0.0/8"), "11.x 不在 10/8")
    check(addressMatches("172.16.0.1", entry: "172.16.0.0/12"), "172.16 命中 /12")
    check(addressMatches("172.31.255.254", entry: "172.16.0.0/12"), "/12 上边界命中")
    check(!addressMatches("172.32.0.1", entry: "172.16.0.0/12"), "172.32 超出 /12")
    check(!addressMatches("172.15.0.1", entry: "172.16.0.0/12"), "172.15 低于 /12")
    // 非 8 的倍数前缀，考验掩码位运算
    check(addressMatches("192.168.1.5", entry: "192.168.1.0/29"), "/29 内")
    check(!addressMatches("192.168.1.9", entry: "192.168.1.0/29"), "/29 外")
    check(addressMatches("1.2.3.4", entry: "0.0.0.0/0"), "/0 匹配一切 IPv4")
    // IPv6
    check(addressMatches("2606:4700::1111", entry: "2606:4700::/32"), "IPv6 /32 命中")
    check(!addressMatches("2607:4700::1111", entry: "2606:4700::/32"), "IPv6 前缀不同")
    // 跨地址族不能互相命中
    check(!addressMatches("8.8.8.8", entry: "2606:4700::/32"), "v4 不匹配 v6 条目")
    check(!addressMatches("::1", entry: "0.0.0.0/0"), "v6 不匹配 v4 的 /0")
    // 垃圾输入
    check(!addressMatches("垃圾", entry: "8.8.8.8"), "非法地址不匹配")
    check(!addressMatches("8.8.8.8", entry: "8.8.8.8/99"), "非法前缀不匹配")
}

func testConnectionGrouping() {
    func make(_ name: String, _ remote: String, _ localPort: String) -> Connection {
        Connection(processName: name, pid: 1, netProtocol: "UDP",
                   localAddress: "198.51.100.2", localPort: localPort,
                   remoteAddress: remote, remotePort: "443")
    }
    // 同进程同目标的多条 socket 合成一行，只是本地端口不同
    let groups = groupConnections([
        make("cloudd", "17.248.224.13", "1"),
        make("cloudd", "17.248.224.13", "2"),
        make("cloudd", "17.248.224.13", "3"),
        make("Safari", "1.1.1.1", "4"),
    ])
    check(groups.count == 2, "合成 2 组（实际 \(groups.count)）")
    guard groups.count == 2 else { return }
    check(groups[0].count == 3, "cloudd 合成 3 条")
    check(groups[1].count == 1, "Safari 单独一条")
    check(groups[0].id != groups[1].id, "两组 id 不同")
    // 本地端口不同的 socket，各自的 id 必须不同，否则列表会错乱
    check(make("a", "1.1.1.1", "1").id != make("a", "1.1.1.1", "2").id, "本地端口计入 id")
    check(groupConnections([]).isEmpty, "空输入不崩")
}

func testConnectionClassification() {
    let tunnels: Set<String> = ["198.51.100.2"]
    let entries = ["203.0.113.10", "10.0.0.0/8"]
    func make(local: String, remote: String) -> Connection {
        Connection(processName: "x", pid: 1, netProtocol: "TCP",
                   localAddress: local, localPort: "5000",
                   remoteAddress: remote, remotePort: "443")
    }
    // 本地地址是 utun 的地址 —— 直接证明这条连接从隧道出去
    check(classify(make(local: "198.51.100.2", remote: "1.1.1.1"),
                   tunnelAddresses: tunnels, allowEntries: entries).label == "走隧道", "隧道连接")
    // 物理网卡出去，目标命中表
    check(classify(make(local: "192.168.1.68", remote: "203.0.113.10"),
                   tunnelAddresses: tunnels, allowEntries: entries).label == "白名单直连", "白名单直连")
    // 物理网卡出去、不在表里 —— 开着防护就会被丢掉
    check(classify(make(local: "192.168.1.68", remote: "1.1.1.1"),
                   tunnelAddresses: tunnels, allowEntries: entries).label == "会被阻断", "会被阻断")
    // 回环走 set skip，压根不过 pf
    check(classify(make(local: "127.0.0.1", remote: "127.0.0.1"),
                   tunnelAddresses: tunnels, allowEntries: entries).label == "本机", "回环")
    check(classify(make(local: "::1", remote: "::1"),
                   tunnelAddresses: tunnels, allowEntries: entries).label == "本机", "IPv6 回环")
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
        testLsofParsing()
        testSplitHostPort()
        testAddressMatching()
        testConnectionGrouping()
        testConnectionClassification()
        testFirewallOptions()
        testDaemonComposesEffectiveList()
        testPreflightPublicEntryDetection()
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
