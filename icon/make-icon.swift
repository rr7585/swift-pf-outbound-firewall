import AppKit
import Foundation

// 画 App 图标，输出一整套 iconset 尺寸的 PNG。
// 纯 CoreGraphics，不依赖任何设计工具，改完重跑 ./icon/build-icon.sh 即可。
//
// 构图：Big Sur 风格的圆角方块底 + 盾牌 + 一支穿过盾牌的上行箭头。
// 盾牌是防护，箭头是「只有走隧道的出站流量能过去」。

// ============================================================================
// 画布规格
// ============================================================================
// Big Sur 以后的图标不铺满画布：1024 的画布里，圆角方块只占 824，四周留白。
// 比例不对的话，图标在 Dock 里会比别人大一圈，非常显眼。
let canvasSize: CGFloat = 1024
let plateSize: CGFloat = 824
let plateRadius: CGFloat = 185

func hex(_ value: UInt32, alpha: CGFloat = 1) -> NSColor {
    NSColor(srgbRed: CGFloat((value >> 16) & 0xFF) / 255,
            green: CGFloat((value >> 8) & 0xFF) / 255,
            blue: CGFloat(value & 0xFF) / 255,
            alpha: alpha)
}

// ============================================================================
// 盾牌
// ============================================================================

/// 盾牌轮廓：上沿平、带圆角，两侧竖直下行后收拢到底部一点。
func shieldPath(in rect: CGRect) -> NSBezierPath {
    let path = NSBezierPath()
    let corner = rect.width * 0.13
    let top = rect.maxY
    let bottom = rect.minY
    let left = rect.minX
    let right = rect.maxX
    let centerX = rect.midX
    // 两侧保持竖直的那一段占全高的比例，再往下开始收拢
    let straight = bottom + rect.height * 0.40

    path.move(to: CGPoint(x: left, y: top - corner))
    path.appendArc(withCenter: CGPoint(x: left + corner, y: top - corner),
                   radius: corner, startAngle: 180, endAngle: 90, clockwise: true)
    path.line(to: CGPoint(x: right - corner, y: top))
    path.appendArc(withCenter: CGPoint(x: right - corner, y: top - corner),
                   radius: corner, startAngle: 90, endAngle: 0, clockwise: true)
    path.line(to: CGPoint(x: right, y: straight))
    // 右侧收拢到底尖
    path.curve(to: CGPoint(x: centerX, y: bottom),
               controlPoint1: CGPoint(x: right, y: bottom + rect.height * 0.17),
               controlPoint2: CGPoint(x: centerX + rect.width * 0.17, y: bottom))
    // 左侧对称地回到竖直段
    path.curve(to: CGPoint(x: left, y: straight),
               controlPoint1: CGPoint(x: centerX - rect.width * 0.17, y: bottom),
               controlPoint2: CGPoint(x: left, y: bottom + rect.height * 0.17))
    path.close()
    return path
}

/// 上行箭头：竖杆 + 三角头，用来从盾牌里挖空。
func arrowPath(in rect: CGRect) -> NSBezierPath {
    let path = NSBezierPath()
    let shaftHalf = rect.width * 0.155
    let headHalf = rect.width * 0.46
    // 箭头「头」只占上半部分的一小截，杆留长一点，否则整支箭显得矮胖
    let headBottom = rect.minY + rect.height * 0.55
    let centerX = rect.midX

    path.move(to: CGPoint(x: centerX, y: rect.maxY))
    path.line(to: CGPoint(x: centerX + headHalf, y: headBottom))
    path.line(to: CGPoint(x: centerX + shaftHalf, y: headBottom))
    path.line(to: CGPoint(x: centerX + shaftHalf, y: rect.minY))
    path.line(to: CGPoint(x: centerX - shaftHalf, y: rect.minY))
    path.line(to: CGPoint(x: centerX - shaftHalf, y: headBottom))
    path.line(to: CGPoint(x: centerX - headHalf, y: headBottom))
    path.close()
    return path
}

// ============================================================================
// 绘制
// ============================================================================
func drawIcon(size: CGFloat) -> Data? {
    let scale = size / canvasSize
    guard let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: Int(size), pixelsHigh: Int(size),
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)
    else { return nil }

    guard let context = NSGraphicsContext(bitmapImageRep: rep) else { return nil }
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = context
    context.imageInterpolation = .high
    // 一次性把画布缩放到目标尺寸，下面所有坐标都按 1024 的画布写。
    context.cgContext.scaleBy(x: scale, y: scale)

    let plateOrigin = (canvasSize - plateSize) / 2
    let plateRect = CGRect(x: plateOrigin, y: plateOrigin, width: plateSize, height: plateSize)
    let plate = NSBezierPath(roundedRect: plateRect, xRadius: plateRadius, yRadius: plateRadius)

    // 底板：深靛蓝到亮蓝的斜向渐变
    let gradient = NSGradient(colors: [hex(0x1D4ED8), hex(0x0B1F5C)],
                             atLocations: [0, 1],
                             colorSpace: .sRGB)
    gradient?.draw(in: plate, angle: -90)

    // 顶部高光，让底板不至于太平
    NSGraphicsContext.saveGraphicsState()
    plate.addClip()
    let sheen = NSGradient(colors: [hex(0xFFFFFF, alpha: 0.22), hex(0xFFFFFF, alpha: 0)],
                           atLocations: [0, 1], colorSpace: .sRGB)
    sheen?.draw(in: CGRect(x: plateRect.minX, y: plateRect.midY,
                           width: plateRect.width, height: plateRect.height / 2),
                angle: -90)
    NSGraphicsContext.restoreGraphicsState()

    // 盾牌
    let shieldWidth = plateSize * 0.58
    let shieldHeight = shieldWidth * 1.24
    let shieldRect = CGRect(x: (canvasSize - shieldWidth) / 2,
                            y: (canvasSize - shieldHeight) / 2 - plateSize * 0.012,
                            width: shieldWidth, height: shieldHeight)
    let shield = shieldPath(in: shieldRect)

    // 盾牌下方一点点阴影，和底板拉开层次
    NSGraphicsContext.saveGraphicsState()
    let shadow = NSShadow()
    shadow.shadowColor = hex(0x000000, alpha: 0.30)
    shadow.shadowBlurRadius = plateSize * 0.045
    shadow.shadowOffset = NSSize(width: 0, height: -plateSize * 0.018)
    shadow.set()
    hex(0xFFFFFF).setFill()
    shield.fill()
    NSGraphicsContext.restoreGraphicsState()

    // 箭头从盾牌里挖空，露出底板的渐变
    let arrowWidth = shieldWidth * 0.56
    let arrowHeight = shieldHeight * 0.62
    let arrowRect = CGRect(x: shieldRect.midX - arrowWidth / 2,
                           y: shieldRect.midY - arrowHeight * 0.44,
                           width: arrowWidth, height: arrowHeight)
    NSGraphicsContext.saveGraphicsState()
    shield.addClip()
    arrowPath(in: arrowRect).addClip()
    gradient?.draw(in: plate, angle: -90)
    NSGraphicsContext.restoreGraphicsState()

    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])
}

// ============================================================================
@main
enum MakeIcon {
    static func main() {
        let outputDir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "."
        // iconset 要求的全套尺寸，少一个 iconutil 就会报错
        let entries: [(String, CGFloat)] = [
            ("icon_16x16.png", 16), ("icon_16x16@2x.png", 32),
            ("icon_32x32.png", 32), ("icon_32x32@2x.png", 64),
            ("icon_128x128.png", 128), ("icon_128x128@2x.png", 256),
            ("icon_256x256.png", 256), ("icon_256x256@2x.png", 512),
            ("icon_512x512.png", 512), ("icon_512x512@2x.png", 1024),
        ]
        for (name, size) in entries {
            guard let data = drawIcon(size: size) else {
                FileHandle.standardError.write(Data("画 \(name) 失败\n".utf8))
                exit(1)
            }
            let url = URL(fileURLWithPath: outputDir).appendingPathComponent(name)
            try? data.write(to: url)
        }
        print("已生成 \(entries.count) 个尺寸")
    }
}
