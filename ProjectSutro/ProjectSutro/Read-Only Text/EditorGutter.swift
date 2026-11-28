//
//  EditorGutter.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/25/26.
//

import AppKit


// MARK: - Gutter
/// The line numbers beside a read-only text, numbered as the text is whatever is folded, the cursor's line darker. A
/// JSON text has a chevron on each line an object or array folds from, down while it's open and right while it's
/// folded, and clicking the line folds or unfolds it. Only the lines on screen are drawn.
final class EditorGutter: NSRulerView {
    private weak var textView: CodeTextView?
    weak var controller: ReadOnlyTextController?
    /// The chevrons' column, for a text that folds.
    private static let chevronWidth: CGFloat = 14

    /// - Parameter textView: The text view, already in its scroll view.
    init(textView: CodeTextView) {
        self.textView = textView
        super.init(scrollView: textView.enclosingScrollView, orientation: .verticalRuler)
        clientView = textView
        ruleThickness = 32
        let center = NotificationCenter.default
        center.addObserver(self, selector: #selector(redraw), name: NSView.boundsDidChangeNotification,
                           object: textView.enclosingScrollView?.contentView)
        /// Lines wrap again as the view's width changes, which moves them.
        center.addObserver(self, selector: #selector(redraw), name: NSView.frameDidChangeNotification, object: textView)
    }

    /// Not used: the gutter is made in code.
    ///
    /// - Parameter coder: Unused.
    required init(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    /// Draw again, as the text scrolls or rewraps.
    @objc private func redraw() { needsDisplay = true }

    /// The line numbers' font, a little smaller than the text.
    private var numberFont: NSFont {
        .monospacedDigitSystemFont(ofSize: max((controller?.textSize ?? 12) - 1.5, 8), weight: .regular)
    }

    /// Does the text fold, so the gutter has chevrons?
    private var folds: Bool { controller?.outline != nil }

    /// Widen or narrow the gutter for the text's last line number and its chevrons.
    func fit() {
        guard let controller else { return }
        let digits = CGFloat(max(String(controller.lines.count).count, 2))
        let digit = ("8" as NSString).size(withAttributes: [.font: numberFont]).width
        let thickness = ceil(digits * digit) + 14 + (folds ? Self.chevronWidth : 0)
        if thickness != ruleThickness {
            ruleThickness = thickness
            scrollView?.tile()
        }
        needsDisplay = true
    }

    /// A chevron, as SF Symbols draws it at the text's size.
    ///
    /// - Parameter folded: Is its object or array folded?
    /// - Returns: `chevron.right` for one folded, `chevron.down` for one open.
    private func chevron(folded: Bool) -> NSImage? {
        let size = max((controller?.textSize ?? 12) * 0.7, 7)
        let configuration = NSImage.SymbolConfiguration(pointSize: size, weight: .semibold)
            .applying(NSImage.SymbolConfiguration(paletteColors: [.secondaryLabelColor]))
        return NSImage(systemSymbolName: folded ? "chevron.right" : "chevron.down",
                       accessibilityDescription: folded ? "Unfold" : "Fold")?
            .withSymbolConfiguration(configuration)
    }

    /// Number each line on screen where it starts, and draw its chevron.
    ///
    /// - Parameter rect: The rectangle to draw.
    override func drawHashMarksAndLabels(in rect: NSRect) {
        guard let textView, let controller, let layoutManager = textView.layoutManager,
              let container = textView.textContainer, let storage = textView.textStorage else { return }
        NSColor.separatorColor.setFill()
        NSRect(x: bounds.maxX - 1, y: bounds.minY, width: 1, height: bounds.height).fill()
        let visible = textView.visibleRect, origin = textView.textContainerOrigin
        let font = numberFont, right = bounds.maxX - 7 - (folds ? Self.chevronWidth : 0)
        let chevrons = [false, true].map { chevron(folded: $0) }
        /// - Parameters:
        ///   - line: A line of the text, from 0.
        ///   - fragment: The line fragment it starts on, in the text container.
        func draw(_ line: Int, in fragment: NSRect) {
            let y = fragment.minY + origin.y - visible.minY
            let color = line == controller.caretLine ? NSColor.labelColor : NSColor.tertiaryLabelColor
            let label = "\(line + 1)" as NSString
            let size = label.size(withAttributes: [.font: font])
            label.draw(at: NSPoint(x: right - size.width, y: y + (fragment.height - size.height) / 2),
                       withAttributes: [.font: font, .foregroundColor: color])
            guard let folded = controller.foldState(onLine: line), let image = chevrons[folded ? 1 : 0] else { return }
            let place = NSRect(x: bounds.maxX - 1 - (Self.chevronWidth + image.size.width) / 2,
                               y: y + (fragment.height - image.size.height) / 2, width: image.size.width,
                               height: image.size.height)
            image.draw(in: place, from: .zero, operation: .sourceOver, fraction: 1, respectFlipped: true, hints: nil)
        }
        if storage.length > 0 {
            let text = storage.mutableString
            let glyphs = layoutManager.glyphRange(forBoundingRect: visible.offsetBy(dx: -origin.x, dy: -origin.y),
                                                  in: container)
            layoutManager.enumerateLineFragments(forGlyphRange: glyphs) { fragment, _, _, range, _ in
                let index = layoutManager.characterIndexForGlyph(at: range.location)
                /// A line that wraps is numbered once, where it starts.
                guard index == 0 || text.character(at: index - 1) == 0x0A else { return }
                draw(controller.line(atShown: index), in: fragment)
            }
        }
        let extra = layoutManager.extraLineFragmentRect
        if extra.height > 0 { draw(controller.lines.count - 1, in: extra) }
    }

    /// Fold or unfold the object or array that opens the line clicked.
    ///
    /// - Parameter event: The click.
    override func mouseDown(with event: NSEvent) {
        guard folds, let textView, let controller, let layoutManager = textView.layoutManager,
              let container = textView.textContainer, let storage = textView.textStorage, storage.length > 0 else {
            return super.mouseDown(with: event)
        }
        let point = convert(event.locationInWindow, from: nil)
        let y = point.y + textView.visibleRect.minY - textView.textContainerOrigin.y
        let glyph = layoutManager.glyphIndex(for: NSPoint(x: 0, y: y), in: container)
        let fragment = layoutManager.lineFragmentRect(forGlyphAt: glyph, effectiveRange: nil)
        guard y >= fragment.minY, y < fragment.maxY else { return }
        let index = layoutManager.characterIndexForGlyph(at: glyph)
        let start = storage.mutableString.lineRange(for: NSRange(location: index, length: 0)).location
        controller.toggleFold(onLine: controller.line(atShown: start))
    }
}
