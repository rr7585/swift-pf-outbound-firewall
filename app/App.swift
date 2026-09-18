import SwiftUI

// PF 出站防火墙 —— 界面层。
// 所有耗时操作（都会弹授权框）丢到后台线程，回主线程更新状态。

@main
struct PFOutboundFirewallApp: App {
    var body: some Scene {
        WindowGroup("PF 出站防火墙") {
            ContentView(model: Model())
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

