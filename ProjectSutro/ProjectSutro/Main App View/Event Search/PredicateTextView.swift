//
//  PredicateTextView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/26/26.
//

import SwiftUI
import AppKit


// MARK: - Text view
/// The editor's text view, for the pane's buttons: inserts at the cursor and reports where the cursor is.
@MainActor
final class PredicateEditorController: ObservableObject {
    weak var textView: NSTextView?
    @Published var line = 1
    @Published var column = 1

    /// Insert text at the cursor, with a space before it unless one's there, and one after.
    ///
    /// - Parameter text: The key path or operator.
    func insert(_ text: String) {
        guard let textView else { return }
        let range = textView.selectedRange()
        let before = (textView.string as NSString).substring(to: range.location)
        let pad = before.isEmpty || before.last?.isWhitespace == true ? "" : " "
        textView.insertText(pad + text + " ", replacementRange: range)
        textView.window?.makeFirstResponder(textView)
    }
}

/// The predicate editor's text: an `NSTextView` with a line number ruler, no smart quotes or dashes, colored as
/// it's typed (``PredicateSyntax``).
struct PredicateTextView: NSViewRepresentable {
    @Binding var text: String
    let editor: PredicateEditorController

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSScrollView {
        let scrollView = NSScrollView()
        scrollView.hasVerticalScroller = true
        scrollView.borderType = .noBorder
        scrollView.drawsBackground = false
        /// TextKit 1, which the line numbers read.
        let textView = CompletingTextView(usingTextLayoutManager: false)
        textView.isVerticallyResizable = true
        textView.autoresizingMask = [.width]
        textView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        textView.textContainer?.widthTracksTextView = true
        scrollView.documentView = textView
        textView.delegate = context.coordinator
        textView.isRichText = false
        textView.allowsUndo = true
        textView.drawsBackground = false
        textView.font = PredicateSyntax.font
        textView.textContainerInset = NSSize(width: 4, height: 8)
        textView.isAutomaticQuoteSubstitutionEnabled = false
        textView.isAutomaticDashSubstitutionEnabled = false
        textView.isAutomaticTextReplacementEnabled = false
        textView.isAutomaticSpellingCorrectionEnabled = false
        textView.isContinuousSpellCheckingEnabled = false
        textView.isGrammarCheckingEnabled = false
        textView.setAccessibilityLabel("Predicate")
        textView.string = text
        PredicateSyntax.highlight(textView.textStorage!)
        scrollView.verticalRulerView = LineNumberRuler(textView: textView)
        scrollView.hasVerticalRuler = true
        scrollView.rulersVisible = true
        scrollView.automaticallyAdjustsContentInsets = false
        /// Views stopped clipping to their bounds in macOS 14. The ruler's line drew past the editor.
        if #available(macOS 14.0, *) {
            scrollView.clipsToBounds = true
            scrollView.verticalRulerView?.clipsToBounds = true
        }
        editor.textView = textView
        return scrollView
    }

    func updateNSView(_ scrollView: NSScrollView, context: Context) {
        context.coordinator.parent = self
        guard let textView = scrollView.documentView as? NSTextView, textView.string != text else { return }
        textView.string = text
        PredicateSyntax.highlight(textView.textStorage!)
        scrollView.verticalRulerView?.needsDisplay = true
    }

    @MainActor
    final class Coordinator: NSObject, NSTextViewDelegate {
        var parent: PredicateTextView

        init(_ parent: PredicateTextView) {
            self.parent = parent
        }

        func textDidChange(_ notification: Notification) {
            guard let textView = notification.object as? NSTextView else { return }
            PredicateSyntax.highlight(textView.textStorage!)
            parent.text = textView.string
            textView.enclosingScrollView?.verticalRulerView?.needsDisplay = true
        }

        func textViewDidChangeSelection(_ notification: Notification) {
            guard let textView = notification.object as? NSTextView else { return }
            let before = (textView.string as NSString).substring(to: textView.selectedRange().location)
            let lines = before.components(separatedBy: "\n")
            let editor = parent.editor
            DispatchQueue.main.async {
                editor.line = lines.count
                editor.column = (lines.last?.count ?? 0) + 1
            }
            textView.enclosingScrollView?.verticalRulerView?.needsDisplay = true
        }
    }
}

/// Line numbers beside the editor's text, the cursor's line darker.
final class LineNumberRuler: NSRulerView {
    private weak var textView: NSTextView?

    /// - Parameter textView: The text view, already in its scroll view.
    init(textView: NSTextView) {
        self.textView = textView
        super.init(scrollView: textView.enclosingScrollView, orientation: .verticalRuler)
        clientView = textView
        ruleThickness = 32
        NotificationCenter.default.addObserver(self, selector: #selector(redraw),
                                               name: NSView.boundsDidChangeNotification,
                                               object: textView.enclosingScrollView?.contentView)
    }

    required init(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    @objc private func redraw() { needsDisplay = true }

    override func drawHashMarksAndLabels(in rect: NSRect) {
        guard let textView, let layoutManager = textView.layoutManager, let container = textView.textContainer else {
            return
        }
        layoutManager.ensureLayout(for: container)
        NSColor.separatorColor.setFill()
        NSRect(x: bounds.maxX - 1, y: bounds.minY, width: 1, height: bounds.height).fill()

        let string = textView.string as NSString
        /// Where each line starts, the empty line after a final newline included.
        var starts = [0]
        for index in 0..<string.length where string.character(at: index) == 10 { starts.append(index + 1) }
        let caret = textView.selectedRange().location
        let visible = textView.visibleRect
        let font = NSFont.monospacedDigitSystemFont(ofSize: 10.5, weight: .regular)
        for (offset, start) in starts.enumerated() {
            let fragment = start < string.length
                ? layoutManager.lineFragmentRect(forGlyphAt: layoutManager.glyphIndexForCharacter(at: start),
                                                 effectiveRange: nil)
                : layoutManager.extraLineFragmentRect
            let y = fragment.minY + textView.textContainerInset.height - visible.minY
            if y > bounds.maxY { break }
            if y + fragment.height < 0 { continue }
            let end = offset + 1 < starts.count ? starts[offset + 1] : string.length + 1
            let attributes: [NSAttributedString.Key: Any] = [
                .font: font,
                .foregroundColor: (start..<end).contains(caret) ? NSColor.labelColor : NSColor.tertiaryLabelColor,
            ]
            let label = "\(offset + 1)" as NSString
            let size = label.size(withAttributes: attributes)
            label.draw(at: NSPoint(x: bounds.maxX - size.width - 7, y: y + (fragment.height - size.height) / 2),
                       withAttributes: attributes)
        }
    }
}
