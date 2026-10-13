import AppKit

/// Draws Fleen's app icon: a rounded-square "app tile" in the macOS idiom, with a key
/// over a shield — the same vocabulary as the menu bar glyph, at a size where detail
/// reads. Generated rather than hand-drawn so it is reproducible and version-controlled
/// as code.
@MainActor func drawIcon(size: CGFloat) -> NSImage {
    let image = NSImage(size: NSSize(width: size, height: size))
    image.lockFocus()
    guard let ctx = NSGraphicsContext.current?.cgContext else { image.unlockFocus(); return image }

    let s = size
    // macOS icons are a squircle inset from the canvas, not edge-to-edge.
    let inset = s * 0.085
    let rect = CGRect(x: inset, y: inset, width: s - inset * 2, height: s - inset * 2)
    let corner = rect.width * 0.2237   // Big Sur's continuous-corner ratio
    let tile = NSBezierPath(roundedRect: rect, xRadius: corner, yRadius: corner)

    // Body: a deep indigo gradient, dark enough for the white glyph to carry.
    let gradient = NSGradient(colors: [
        NSColor(srgbRed: 0.22, green: 0.28, blue: 0.52, alpha: 1),
        NSColor(srgbRed: 0.10, green: 0.13, blue: 0.29, alpha: 1),
    ])!
    tile.addClip()
    gradient.draw(in: rect, angle: -90)

    // A soft top-left sheen, so the tile reads as a surface rather than a flat swatch.
    ctx.saveGState()
    let sheen = NSGradient(colors: [NSColor(white: 1, alpha: 0.18), NSColor(white: 1, alpha: 0)])!
    sheen.draw(in: CGRect(x: rect.minX, y: rect.midY, width: rect.width, height: rect.height / 2),
               angle: -90)
    ctx.restoreGState()

    // Shield outline.
    let w = rect.width
    let shield = NSBezierPath()
    let cx = rect.midX
    let top = rect.minY + w * 0.80
    let bottom = rect.minY + w * 0.17
    let halfW = w * 0.235
    shield.move(to: CGPoint(x: cx, y: top))
    shield.line(to: CGPoint(x: cx + halfW, y: top - w * 0.145))
    shield.curve(to: CGPoint(x: cx, y: bottom),
                 controlPoint1: CGPoint(x: cx + halfW, y: bottom + w * 0.30),
                 controlPoint2: CGPoint(x: cx + halfW * 0.72, y: bottom + w * 0.045))
    shield.curve(to: CGPoint(x: cx - halfW, y: top - w * 0.145),
                 controlPoint1: CGPoint(x: cx - halfW * 0.72, y: bottom + w * 0.045),
                 controlPoint2: CGPoint(x: cx - halfW, y: bottom + w * 0.30))
    shield.close()
    NSColor(white: 1, alpha: 0.95).setStroke()
    shield.lineWidth = max(1, w * 0.045)
    shield.lineJoinStyle = .round
    shield.stroke()

    // Keyhole: circle plus stem, the universal "this holds a secret" mark.
    let holeR = w * 0.072
    let holeY = rect.minY + w * 0.515
    let hole = NSBezierPath(ovalIn: CGRect(x: cx - holeR, y: holeY - holeR,
                                           width: holeR * 2, height: holeR * 2))
    NSColor(white: 1, alpha: 0.95).setFill()
    hole.fill()
    let stem = NSBezierPath(roundedRect: CGRect(x: cx - w * 0.028, y: holeY - w * 0.155,
                                                width: w * 0.056, height: w * 0.135),
                            xRadius: w * 0.028, yRadius: w * 0.028)
    stem.fill()

    image.unlockFocus()
    return image
}

let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "Fleen.iconset"
try? FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: true)

// The sizes `iconutil` expects.
let variants: [(name: String, px: CGFloat)] = [
    ("icon_16x16", 16), ("icon_16x16@2x", 32),
    ("icon_32x32", 32), ("icon_32x32@2x", 64),
    ("icon_128x128", 128), ("icon_128x128@2x", 256),
    ("icon_256x256", 256), ("icon_256x256@2x", 512),
    ("icon_512x512", 512), ("icon_512x512@2x", 1024),
]
MainActor.assumeIsolated {
    for variant in variants {
        let image = drawIcon(size: variant.px)
        guard let tiff = image.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff),
              let png = rep.representation(using: .png, properties: [:]) else { continue }
        try? png.write(to: URL(fileURLWithPath: "\(out)/\(variant.name).png"))
    }
    print("wrote \(variants.count) sizes to \(out)")
}
