import SwiftUI
import AppKit

// PF 出站防火墙 —— 界面层。
// 所有耗时操作（都会弹授权框）丢到后台线程，回主线程更新状态。

@main
struct PFOutboundFirewallApp: App {
    var body: some Scene {
        WindowGroup("PF 出站防火墙") {
            ContentView()
        }
        // 窗口开出来就是内容的最小尺寸，所以最小尺寸即初始尺寸
        // （试过 .defaultSize 和 .frame(idealWidth:) 都不生效）。
        // 用户拖过之后 AppKit 会把 NSWindow Frame 记进 defaults，下次还原。
        //
        // 这里千万别加 .windowResizability(.contentMinSize)：
        // 它把窗口最小尺寸钉死在内容最小尺寸上，而 AllowlistEditor 包着的
        // NSScrollView 会报一个很大的固有尺寸，于是窗口最小宽度变成 900pt，
        // 小屏上根本缩不小。更隐蔽的是，“未安装”状态下编辑器压根没显示，
        // if/else 的另一个分支照样参与这个计算，一样会把窗口撑大。
        // 用默认的 .automatic，最小尺寸由下面 ContentView 的 frame 说了算。
        .commands {
            // 单窗口工具，去掉“新建窗口”。撤销/剪切/复制/粘贴/全选
            // 由 SwiftUI 的标准“编辑”菜单自动提供。
            CommandGroup(replacing: .newItem) {}
        }
    }
}

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

    var statusText: String {
        if !installed { return "尚未安装" }
        return protected ? "已安装，防护已开启" : "已安装，防护已关闭"
    }

    var statusColor: Color {
        if !installed { return .secondary }
        return protected ? .green : .orange
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

    func toggleProtection() {
        if protected {
            run("正在关闭防护 …", reloadList: false) {
                try disableProtection()
                return "防护已关闭"
            }
            return
        }
        guard checkAllowlist() else { return }
        let text = listText
        run("正在启用防护 …", reloadList: false) {
            try enableProtection(listText: text)
            return "防护已开启"
        }
    }

    func uninstall() {
        run("正在卸载 …", reloadList: true) {
            try uninstallFirewall()
            return nil
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
            message: "“\(issue.text)” 不是有效的 IPv4 或 IPv4/CIDR。\n例如：8.8.8.8 或 192.168.1.0/24")
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
struct ContentView: View {
    @StateObject private var model = Model()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 6) {
                Circle().fill(model.statusColor).frame(width: 9, height: 9)
                Text(model.statusText).font(.headline)
                if model.busy {
                    ProgressView().controlSize(.small).padding(.leading, 4)
                    Text(model.busyLabel).font(.caption).foregroundStyle(.secondary)
                } else if !model.note.isEmpty {
                    Text("· " + model.note).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }

            if model.legacyInstall {
                HStack(spacing: 8) {
                    Text("旧版安装：改白名单仍需密码")
                        .font(.caption).foregroundStyle(.orange)
                    Button("升级") { model.reinstall() }
                        .controlSize(.small)
                    Spacer()
                }
            }

            if model.installed {
                installedView
            } else {
                notInstalledView
            }
        }
        .padding(16)
        .frame(minWidth: 560, minHeight: 440)
        .disabled(model.busy)
        .alert(item: $model.alert) { box in
            Alert(title: Text(box.title), message: Text(box.message),
                  dismissButton: .default(Text("确定")))
        }
        .confirmationDialog("确定卸载？", isPresented: $model.askUninstall) {
            Button("卸载", role: .destructive) { model.uninstall() }
            Button("取消", role: .cancel) {}
        } message: {
            Text("这会关闭 PF、移除开机自启并删除全部相关文件。")
        }
    }

    private var installedView: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(model.legacyInstall
                 ? "允许直连的目的 IP / CIDR（每行一个，# 开头为注释）"
                 : "允许直连的目的 IP / CIDR（每行一个，# 开头为注释）· 保存无需密码")
                .font(.caption).foregroundStyle(.secondary)

            AllowlistEditor(text: $model.listText, highlight: $model.highlight)

            HStack(spacing: 10) {
                Button("保存并生效") { model.saveOrInstall() }
                    .keyboardShortcut(.defaultAction)
                Button(model.protected ? "关闭防护" : "启用防护") { model.toggleProtection() }
                Spacer()
                Button("卸载") { model.askUninstall = true }
            }
        }
    }

    private var notInstalledView: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("安装后将默认阻断全部出站流量，只放行 lo0、utun0~9 和白名单地址。\n"
                + "安装需要管理员密码。")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Spacer()
            Button("安装并启用") { model.saveOrInstall() }
                .keyboardShortcut(.defaultAction)
        }
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
        scrollView.borderType = .bezelBorder
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true

        if let textView = scrollView.documentView as? NSTextView {
            textView.delegate = context.coordinator
            textView.isRichText = false          // 粘贴时丢掉样式，只要纯文本
            textView.isAutomaticQuoteSubstitutionEnabled = false
            textView.isAutomaticDashSubstitutionEnabled = false
            textView.isAutomaticTextReplacementEnabled = false
            textView.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
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
