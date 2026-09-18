import SwiftUI
import AppKit

// 把界面离屏渲染成 PNG，用来在没有录屏权限的机器上检查排版。
// 不是产品的一部分，只在开发时手动跑：
//   swiftc -O app/Rules.swift app/Core.swift app/ContentView.swift tools/render-ui.swift -o /tmp/render
//   /tmp/render <输出目录>

@MainActor
func snapshot(_ name: String, width: CGFloat, height: CGFloat,
              into dir: String, dark: Bool = false, configure: (Model) -> Void) {
    let model = Model()
    configure(model)
    let view = ContentView(model: model)
        .frame(width: width, height: height)
        .environment(\.colorScheme, dark ? .dark : .light)
    let renderer = ImageRenderer(content: view)
    renderer.scale = 2
    // 语义色（controlBackgroundColor 等）要有 NSAppearance 才解析得出来，
    // 否则深浅两套都会渲染成同一个白底，看不出卡片层次。
    NSAppearance(named: dark ? .darkAqua : .aqua)?.performAsCurrentDrawingAppearance {}
    var rendered: NSImage?
    NSAppearance(named: dark ? .darkAqua : .aqua)?.performAsCurrentDrawingAppearance {
        rendered = renderer.nsImage
    }
    guard let image = rendered,
          let tiff = image.tiffRepresentation,
          let png = NSBitmapImageRep(data: tiff)?.representation(using: .png, properties: [:])
    else {
        print("❌ \(name) 渲染失败")
        return
    }
    try? png.write(to: URL(fileURLWithPath: dir).appendingPathComponent("\(name).png"))
    print("✅ \(name)")
}

@main
enum Render {
    static func main() {
        let dir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "."
        let sample = """
        # WireGuard 节点
        203.0.113.10

        # 局域网
        10.0.0.0/8
        192.168.0.0/16
        2606:4700::/32
        """
        MainActor.assumeIsolated {
            snapshot("1-未安装", width: 560, height: 300, into: dir) { m in
                m.installed = false; m.protected = false; m.listText = ""
            }
            snapshot("2-防护开启", width: 560, height: 480, into: dir) { m in
                m.installed = true; m.protected = true; m.listText = sample
            }
            snapshot("2d-防护开启-深色", width: 560, height: 480, into: dir, dark: true) { m in
                m.installed = true; m.protected = true; m.listText = sample
            }
            snapshot("1d-未安装-深色", width: 560, height: 300, into: dir, dark: true) { m in
                m.installed = false; m.protected = false; m.listText = ""
            }
            snapshot("3-防护关闭", width: 560, height: 480, into: dir) { m in
                m.installed = true; m.protected = false; m.listText = sample
            }
            snapshot("4-处理中", width: 560, height: 480, into: dir) { m in
                m.installed = true; m.protected = true; m.listText = sample
                m.busy = true; m.busyLabel = "正在保存 …"
            }
            snapshot("7-连接面板", width: 640, height: 520, into: dir) { m in
                m.installed = true; m.protected = true; m.listText = sample
                m.panel = .connections
                m.connections = [
                    ("某个应用", "142.250.4.188:5228", "TCP", ConnectionVerdict.blocked),
                    ("claude.exe", "160.79.104.10:443", "TCP", .tunnel),
                    ("cloudd", "17.248.224.13:443", "UDP", .tunnel),
                    ("WireGuard", "203.0.113.10:30102", "UDP", .allowlisted),
                ].map { name, remote, proto, verdict in
                    let parts = remote.components(separatedBy: ":")
                    return Model.ConnectionRow(
                        connection: Connection(processName: name, pid: 1, netProtocol: proto,
                                               localAddress: "192.168.1.68", localPort: "5000",
                                               remoteAddress: parts[0], remotePort: parts[1]),
                        count: 1, verdict: verdict)
                }
            }
            snapshot("6-高级选项展开", width: 560, height: 620, into: dir) { m in
                m.installed = true; m.protected = true; m.listText = sample
                m.showAdvanced = true
            }
            snapshot("5-旧版安装", width: 560, height: 480, into: dir) { m in
                m.installed = true; m.protected = true; m.listText = sample
                m.legacyInstall = true
            }
        }
    }
}
