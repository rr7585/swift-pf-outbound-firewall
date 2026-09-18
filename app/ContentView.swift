import SwiftUI
import AppKit

// PF 出站防火墙 —— 界面。
// 所有耗时操作（都会弹授权框）丢到后台线程，回主线程更新状态。

struct AlertBox: Identifiable {
    let id = UUID()
    let title: String
    let message: String
}

// ============================================================================
// 状态
// ============================================================================
@MainActor
final class Model: ObservableObject {
    @Published var listText = readAllowlist()
    @Published var installed = isInstalled()
    @Published var protected = isProtected()
    @Published var busy = false
    @Published var busyLabel = ""
    @Published var alert: AlertBox?
    @Published var askUninstall = false
    /// 上一次操作的结果，显示在状态行旁边（守护进程回报的那句话）。
    @Published var note = ""
    /// 旧版安装：LaunchDaemon 没有 WatchPaths，保存白名单还得输密码。
    @Published var legacyInstall = isInstalled() && !installSupportsWatchPaths()
    /// 校验失败时要在编辑器里选中的范围，一次性。
    @Published var highlight: NSRange?
    @Published var showAdvanced = false
    @Published var options = readOptions() {
        didSet {
            guard options != oldValue, installed, !applyingOptions else { return }
            applyOptions()
        }
    }
    /// 从磁盘回填选项时不要反过来又写一遍磁盘。
    private var applyingOptions = false
    /// 开启防护前的预检提示；nil 表示没问题。
    @Published var preflight: AlertBox?

    var statusTitle: String {
        if !installed { return "尚未安装" }
        return protected ? "防护已开启" : "防护已关闭"
    }

    var statusDetail: String {
        if !installed { return "安装后即可开始防护，随时可以卸载" }
        let count = validEntryCount
        let suffix = count == 0 ? "白名单为空" : "白名单 \(count) 条"
        return protected ? "正在阻断非隧道出站流量 · \(suffix)" : "出站流量不受限制 · \(suffix)"
    }

    /// SF Symbol：装了且开着是对勾盾牌，关了是斜杠盾牌，没装是空盾牌。
    var statusSymbol: String {
        if !installed { return "shield" }
        return protected ? "checkmark.shield.fill" : "shield.slash.fill"
    }

    var statusTint: Color {
        if !installed { return .secondary }
        return protected ? .green : .orange
    }

    /// 排掉空行和注释，只数真正生效的条目。
    var validEntryCount: Int {
        listText.split(separator: "\n").filter {
            let line = $0.trimmingCharacters(in: .whitespaces)
            return !line.isEmpty && !line.hasPrefix("#")
        }.count
    }

    // ------------------------------------------------------------------
    // 操作
    // ------------------------------------------------------------------

    func saveOrInstall() {
        guard checkAllowlist() else { return }
        let text = listText
        let wasInstalled = installed
        let shouldApply = protected
        run(wasInstalled ? "正在保存 …" : "正在安装 …", reloadList: true) {
            guard wasInstalled else {
                try installAndEnable()
                return "已安装并启用"
            }
            guard installSupportsWatchPaths() else {
                try saveAllowlist(text, apply: shouldApply)
                return "已保存"
            }
            // 免密：只写文件，重载由 WatchPaths 触发的守护进程完成。
            guard let status = try saveAllowlistWithoutPassword(text) else {
                return "已保存，但等守护进程确认超时"
            }
            if !status.ok { throw FirewallError.failed(status.detail) }
            return status.detail
        }
    }

    /// 高级选项改了就直接落盘 —— 文件被 WatchPaths 监视，守护进程会自己重载。
    private func applyOptions() {
        let snapshot = options
        run("正在应用选项 …", reloadList: false) {
            let before = try? saveOptionsAndWait(snapshot)
            return before?.detail ?? "选项已更新"
        }
    }

    func toggleProtection() {
        if protected {
            run("正在关闭防护 …", reloadList: false) {
                try disableProtection()
                return "防护已关闭"
            }
            return
        }
        guard checkAllowlist() else { return }
        // 预检：默认路由走隧道、但白名单里一个公网地址都没有 —— 这时开防护
        // 会把通往 VPN 节点的连接一起挡掉，隧道随即断开，整个网络都没了。
        if defaultRouteGoesThroughTunnel(), !allowlistHasPublicEntry(listText) {
            preflight = AlertBox(
                title: "白名单里没有 VPN 节点地址",
                message: "当前网络流量正走隧道，而白名单里没有任何公网地址。"
                    + "开启防护会连同通往 VPN 节点的连接一起阻断，隧道会断开、网络将不可用。\n\n"
                    + "请先把 VPN 服务器的 IP 加进白名单。")
            return
        }
        startProtection()
    }

    /// 预检提示里选择“仍然开启”时走这里。
    func startProtection() {
        let text = listText
        run("正在启用防护 …", reloadList: false) {
            try enableProtection(listText: text)
            return "防护已开启"
        }
    }

    /// keepConfig：只停服务、清规则，把白名单留在原地，下次安装直接沿用。
    func uninstall(keepConfig: Bool) {
        run("正在卸载 …", reloadList: true) {
            try uninstallFirewall(keepConfig: keepConfig)
            return keepConfig ? "已卸载，白名单已保留" : nil
        }
    }

    /// 旧版安装升级成带 WatchPaths 的新版。安装脚本本身是幂等的，重跑即可。
    func reinstall() {
        run("正在升级安装 …", reloadList: true) {
            try installAndEnable()
            return "已升级，之后改白名单不再需要密码"
        }
    }

    // ------------------------------------------------------------------
    // 内部
    // ------------------------------------------------------------------

    /// 校验不通过时选中出错的那行并提示，返回 false。
    private func checkAllowlist() -> Bool {
        guard installed, let issue = validateAllowlist(listText) else { return true }
        highlight = issue.range
        alert = AlertBox(
            title: "白名单第 \(issue.lineNumber) 行格式错误",
            message: "“\(issue.text)” 不是有效的 IP 地址或网段。\n"
                + "例如：8.8.8.8、192.168.1.0/24、2001:4860:4860::8888、2606:4700::/32")
        return false
    }

    /// reloadList：成功后是否用磁盘上的内容覆盖编辑框。
    /// 失败时一律不覆盖，否则用户刚敲的白名单就没了。
    private func run(_ label: String,
                     reloadList: Bool,
                     _ work: @escaping @Sendable () throws -> String?) {
        guard !busy else { return }
        busy = true
        busyLabel = label
        note = ""
        Task.detached(priority: .userInitiated) {
            var failure: String?
            var outcome: String?
            do {
                outcome = try work()
            } catch FirewallError.cancelled {
                // 用户自己点的取消，不报错
            } catch {
                failure = String(describing: error)
            }
            let message = failure
            let result = outcome
            await MainActor.run {
                self.busy = false
                self.installed = isInstalled()
                self.protected = isProtected()
                self.legacyInstall = self.installed && !installSupportsWatchPaths()
                self.applyingOptions = true
                self.options = readOptions()
                self.applyingOptions = false
                if let message {
                    self.alert = AlertBox(title: "操作失败", message: message)
                } else {
                    self.note = result ?? ""
                    if reloadList { self.listText = readAllowlist() }
                }
            }
        }
    }
}

// ============================================================================
// 界面
// ============================================================================

/// 系统设置那种「浅灰底 + 圆角白卡片」的分组外观。
/// 不用 SwiftUI 的 Form(.grouped)：它底层是 AppKit 的，ImageRenderer 离屏
/// 渲染不出来，开发时就没法用 tools/render-ui.swift 检查排版。手写反而可控。
private struct Card<Content: View>: View {
    var padding: CGFloat = 16
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color(nsColor: .controlBackgroundColor)))
            // 单靠语义色的明度差在某些外观下几乎看不出来，补一道细边框定住卡片轮廓。
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(Color.primary.opacity(0.09)))
    }
}

struct ContentView: View {
    @ObservedObject var model: Model

    var body: some View {
        VStack(spacing: 0) {
            // 不套 ScrollView：这里该是「编辑器随窗口长高」，而不是整页滚动。
            // 顺带 ImageRenderer 也能离屏渲染，tools/render-ui.swift 才有用。
            VStack(alignment: .leading, spacing: 18) {
                Card { statusRow }
                if model.installed {
                    allowlistSection
                    advancedSection
                } else {
                    welcomeCard
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .background(Color(nsColor: .windowBackgroundColor))

            Divider()
            actionBar
        }
        .frame(minWidth: 540, minHeight: model.installed ? 500 : 300)
        .disabled(model.busy)
        .alert(item: $model.alert) { box in
            Alert(title: Text(box.title), message: Text(box.message),
                  dismissButton: .default(Text("好")))
        }
        .alert(item: $model.preflight) { box in
            Alert(title: Text(box.title),
                  message: Text(box.message),
                  primaryButton: .default(Text("去添加")) {},
                  secondaryButton: .destructive(Text("仍然开启")) { model.startProtection() })
        }
        .confirmationDialog("要卸载 PF 出站防火墙吗？", isPresented: $model.askUninstall) {
            Button("卸载并保留白名单") { model.uninstall(keepConfig: true) }
            Button("卸载并删除全部配置", role: .destructive) { model.uninstall(keepConfig: false) }
            Button("取消", role: .cancel) {}
        } message: {
            Text("两种方式都会关闭防护并移除开机自启。保留白名单的话，下次安装会直接沿用。")
        }
    }

    // ------------------------------------------------------------------
    // 状态卡片
    // ------------------------------------------------------------------
    private var statusRow: some View {
        HStack(spacing: 14) {
            Image(systemName: model.statusSymbol)
                .font(.system(size: 28))
                .foregroundStyle(model.statusTint)
                .frame(width: 34)

            VStack(alignment: .leading, spacing: 3) {
                Text(model.statusTitle).font(.system(size: 15, weight: .semibold))
                Text(model.statusDetail).font(.subheadline).foregroundStyle(.secondary)
            }

            Spacer(minLength: 12)

            if model.installed {
                Toggle("", isOn: Binding(get: { model.protected },
                                         set: { _ in model.toggleProtection() }))
                    .toggleStyle(.switch)
                    .labelsHidden()
                    .accessibilityLabel("防护开关")
            }
        }
    }

    // ------------------------------------------------------------------
    // 白名单
    // ------------------------------------------------------------------
    private var allowlistSection: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text("允许直连的地址")
                .font(.subheadline.weight(.medium))
                .foregroundStyle(.secondary)
                .padding(.leading, 4)

            // 编辑器本身就是这张卡片：不再嵌一层内边框，内缩交给
            // NSTextView 的 textContainerInset 去做，观感更接近系统设置。
            Card(padding: 0) {
                AllowlistEditor(text: $model.listText, highlight: $model.highlight)
                    .frame(minHeight: 170, maxHeight: .infinity)
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            }

            Text("每行一个 IP 或网段，IPv4 与 IPv6 均可，# 开头为注释。"
                 + (model.legacyInstall ? "" : "修改后保存无需密码。"))
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.leading, 4)
        }
    }

    // ------------------------------------------------------------------
    // 高级选项
    // ------------------------------------------------------------------
    private var advancedSection: some View {
        DisclosureGroup(isExpanded: $model.showAdvanced) {
            Card(padding: 0) {
                VStack(spacing: 0) {
                    optionRow(title: "允许局域网访问",
                              detail: "放行 10/8、172.16/12、192.168/16 私有网段，"
                                    + "用于访问路由器后台、NAS 等设备",
                              isOn: $model.options.allowLAN)
                    Divider().padding(.leading, 16)
                    optionRow(title: "允许 DHCP 广播",
                              detail: "放行 255.255.255.255，"
                                    + "否则租约到期或重连 Wi-Fi 时可能拿不到 IP 地址",
                              isOn: $model.options.allowDHCP)
                }
            }
            .padding(.top, 7)
        } label: {
            Text("高级选项")
                .font(.subheadline.weight(.medium))
                .foregroundStyle(.secondary)
        }
        .padding(.leading, 4)
    }

    private func optionRow(title: String, detail: String, isOn: Binding<Bool>) -> some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.callout)
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            Toggle("", isOn: isOn).toggleStyle(.switch).labelsHidden()
        }
        .padding(16)
    }

    private var welcomeCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                ForEach(Array(Self.features.enumerated()), id: \.offset) { _, item in
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: item.symbol)
                            .foregroundStyle(.tint)
                            .frame(width: 18)
                        Text(item.text)
                            .font(.callout)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
    }

    private static let features: [(symbol: String, text: String)] = [
        ("lock.shield", "默认阻断全部出站流量，只放行本机回环、utun 虚拟网卡和白名单地址"),
        ("bolt.horizontal.circle", "VPN 断线或分流失效时，流量不会回落到物理网卡，真实 IP 不泄漏"),
        ("power", "开机自动生效，无需每次手动开启"),
        ("key", "安装需要管理员密码；之后修改白名单不再需要"),
    ]

    // ------------------------------------------------------------------
    // 底部操作栏
    // ------------------------------------------------------------------
    private var actionBar: some View {
        HStack(spacing: 10) {
            if model.installed {
                Button("卸载…") { model.askUninstall = true }
            }
            if model.legacyInstall {
                Label("旧版安装，保存仍需密码", systemImage: "exclamationmark.triangle.fill")
                    .font(.callout).foregroundStyle(.orange)
                Button("升级") { model.reinstall() }
            }

            Spacer(minLength: 8)

            if model.busy {
                ProgressView().controlSize(.small)
                Text(model.busyLabel).font(.callout).foregroundStyle(.secondary)
            } else if !model.note.isEmpty {
                Label(model.note, systemImage: "checkmark.circle.fill")
                    .font(.callout).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.tail)
            }

            Button(model.installed ? "保存并生效" : "安装并启用") { model.saveOrInstall() }
                .keyboardShortcut(.defaultAction)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
        .background(.bar)
    }
}

// ============================================================================
// 白名单编辑器
// ============================================================================

/// 包一层 NSTextView：SwiftUI 的 TextEditor 没法按范围选中+滚动，
/// 而“校验失败时把光标定位到出错那行”是这个工具最实用的细节之一。
struct AllowlistEditor: NSViewRepresentable {
    @Binding var text: String
    @Binding var highlight: NSRange?

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    /// 编辑器完全跟随容器尺寸，不参与最小尺寸计算。
    ///
    /// 不实现这个方法的话，SwiftUI 会去问 NSScrollView 的固有尺寸，
    /// 而它是个很大的值 —— 于是窗口最小宽度被顶到 900pt，defaultSize 被撑掉。
    /// 更坑的是：即使“未安装”状态下这个编辑器压根没显示，
    /// if/else 的另一个分支照样参与窗口最小尺寸计算，一样会把窗口撑大。
    func sizeThatFits(_ proposal: ProposedViewSize,
                      nsView: NSScrollView,
                      context: Context) -> CGSize? {
        CGSize(width: proposal.width ?? 320, height: proposal.height ?? 160)
    }

    func makeNSView(context: Context) -> NSScrollView {
        let scrollView = NSTextView.scrollableTextView()
        scrollView.borderType = .noBorder   // 边框由 SwiftUI 那边画，两套叠起来很丑
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true

        if let textView = scrollView.documentView as? NSTextView {
            textView.delegate = context.coordinator
            textView.isRichText = false          // 粘贴时丢掉样式，只要纯文本
            textView.isAutomaticQuoteSubstitutionEnabled = false
            textView.isAutomaticDashSubstitutionEnabled = false
            textView.isAutomaticTextReplacementEnabled = false
            textView.font = .monospacedSystemFont(ofSize: 12.5, weight: .regular)
            textView.textContainerInset = NSSize(width: 12, height: 12)
            textView.string = text
        }
        return scrollView
    }

    func updateNSView(_ scrollView: NSScrollView, context: Context) {
        context.coordinator.parent = self
        guard let textView = scrollView.documentView as? NSTextView else { return }
        if textView.string != text {
            textView.string = text
        }
        if let range = highlight, range.upperBound <= textView.string.utf16.count {
            textView.setSelectedRange(range)
            textView.scrollRangeToVisible(range)
            textView.window?.makeFirstResponder(textView)
            // 选中是一次性动作；不清掉的话每次重绘都会抢焦点。
            DispatchQueue.main.async { self.highlight = nil }
        }
    }

    final class Coordinator: NSObject, NSTextViewDelegate {
        var parent: AllowlistEditor
        init(_ parent: AllowlistEditor) { self.parent = parent }

        func textDidChange(_ notification: Notification) {
            guard let textView = notification.object as? NSTextView else { return }
            parent.text = textView.string
        }
    }
}
