//
//  ReadOnlyTextController.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/25/26.
//

import AppKit
import SwiftUI
import SutroESFramework


// MARK: - Status
/// Where the cursor is in a read-only text and what the text is, for its status bar and key path bar. It's apart from
/// the controller, so moving the cursor redraws the bars and not the text.
@MainActor
final class EditorStatus: ObservableObject {
    /// The cursor's line and column, from 1, in the text's own numbering whatever is folded. A column far along a
    /// long line counts UTF-16 units.
    @Published var line = 1
    @Published var column = 1
    /// How many characters are selected, or UTF-16 units for a long selection.
    @Published var selected = 0
    /// The keys to the value at the cursor, in an event's record.
    @Published var keyPath: [String] = []
    /// Is the record a network flow's, whose keys the schema describes apart (``RecordKeyPaths/networkNodes``)?
    @Published var isNetworkRecord = false
    /// The text's language as the status bar names it.
    @Published var language = ""
    /// How many lines the text has. A final line feed doesn't start another.
    @Published var lineCount = 1
    /// The text's size in UTF-8 bytes.
    @Published var byteCount = 0
    /// Is Go to Line's field showing?
    @Published var isGoingToLine = false
}


// MARK: - Controller
/// A read-only text view's model: the text, its lines and, for JSON, its outline, colored for its language and folded
/// (ReadOnlyTextController+Folding.swift). It shows the text in a ``CodeTextView`` and keeps ``status`` up to date as
/// the selection moves.
///
/// Offsets in the text shown differ from the text's own once something folds. Everything kept here is in the text's
/// own offsets, mapped through ``folds`` to and from the view.
@MainActor
final class ReadOnlyTextController: NSObject, ObservableObject, NSTextViewDelegate {
    let status = EditorStatus()
    /// Is anything folded, for Unfold All?
    @Published private(set) var isFolded = false
    /// Can anything inside the top value fold, for Fold All?
    @Published private(set) var canFold = false
    /// Does the key path bar follow the cursor, and right-clicking a value offer its key path and predicate?
    var readsKeyPaths = false

    private(set) weak var textView: CodeTextView?
    private(set) weak var gutter: EditorGutter?

    /// The text shown, `nil` until a text view shows it.
    private(set) var text: String?
    /// The same text as an `NSString`, which reads a UTF-16 offset in constant time.
    private(set) var original: NSString = ""
    private(set) var language = ReadOnlyTextView.Language.plain
    private(set) var lines = TextLines("")
    /// A JSON text's objects, arrays and values.
    private(set) var outline: JSONOutline?
    /// The text colored for its language at the text size, before it's folded.
    private var colored = NSAttributedString()
    /// The objects and arrays folded, by their place in the outline's containers.
    var folded: Set<Int> = []
    /// The folds shown, the outermost of those folded.
    var folds = TextFolds.none
    private(set) var textSize = CGFloat(EditorPreferences.defaultSize)
    private(set) var wrapsLines = true
    /// The cursor's line, from 0, which the gutter numbers darker.
    private(set) var caretLine = 0
    /// The brackets highlighted, in the text shown.
    private var brackets: [NSRange] = []

    /// The placeholder's colors, a bubble as Xcode draws a fold.
    private static let placeholderBackground = NSColor.appearance(light: .hex(0xE4E7EB), dark: .hex(0x3A3D42))
    /// A bracket that matches the one at the cursor.
    private static let bracketBackground = NSColor.appearance(light: .hex(0xD3D8DF), dark: .hex(0x4A4F57))

    // MARK: Showing
    /// Show text in a text view and number it in a gutter.
    ///
    /// - Parameters:
    ///   - textView: The text view.
    ///   - gutter: Its gutter.
    func attach(_ textView: CodeTextView, gutter: EditorGutter) {
        textView.delegate = self
        textView.controller = self
        gutter.controller = self
        self.textView = textView
        self.gutter = gutter
        text = nil
    }

    /// Show a text, unless it's the one shown. A new text starts unfolded, at the top.
    ///
    /// - Parameters:
    ///   - text: The text.
    ///   - language: What it is, for its colors.
    func show(_ text: String, language: ReadOnlyTextView.Language) {
        guard text != self.text || language != self.language, let textView else { return }
        clearBrackets()
        self.text = text
        self.language = language
        original = NSString(string: text)
        outline = language == .json ? JSONOutline(text) : nil
        lines = outline?.lines ?? TextLines(text)
        folded = []
        folds = .none
        recolor()
        textView.textStorage?.setAttributedString(colored)
        textView.setSelectedRange(NSRange(location: 0, length: 0))
        textView.scrollToBeginningOfDocument(nil)
        gutter?.fit()
        /// Fold All folds what's inside each value at the top.
        let canFold = outline.map { outline in
            outline.containers.contains { $0.isFoldable && outline.values[$0.value].parent != nil }
        } ?? false
        let name = language == .json ? language.rawValue
            : ReadOnlyTextView.Language.interpreter(of: text) ?? language.rawValue
        let (lineCount, byteCount) = (text.lineCount, text.utf8.count)
        let isNetworkRecord = outline.map(RecordKeyPaths.isNetworkRecord) == true
        publish { controller in
            controller.isFolded = false
            controller.canFold = canFold
            controller.status.language = name
            controller.status.lineCount = lineCount
            controller.status.byteCount = byteCount
            controller.status.isNetworkRecord = isNetworkRecord
        }
        selectionChanged()
    }

    /// Set the text's size and wrapping, as Settings keeps them for every read-only text view.
    ///
    /// - Parameters:
    ///   - textSize: The text's size, in points.
    ///   - wrapsLines: Wrap long lines, rather than scroll sideways?
    func apply(textSize: CGFloat, wrapsLines: Bool) {
        guard let textView else { return }
        if wrapsLines != self.wrapsLines || textView.wrapsLines != wrapsLines {
            self.wrapsLines = wrapsLines
            textView.wrapsLines = wrapsLines
            gutter?.needsDisplay = true
        }
        guard textSize != self.textSize else { return }
        self.textSize = textSize
        recolor()
        keepingPlace {
            textView.textStorage?.setAttributedString(rendered(NSRange(location: 0, length: original.length)))
        }
        gutter?.fit()
    }

    /// Color the text for its language at the text size.
    private func recolor() {
        let text = NSMutableAttributedString(string: original as String, attributes: [
            .font: PredicateSyntax.monospaced(size: textSize), .foregroundColor: NSColor.textColor,
        ])
        language.color(text, size: textSize)
        colored = text
    }

    /// What the view shows for a range of the text: its colored text, with each shown fold's placeholder.
    ///
    /// - Parameter range: A range of the text that no shown fold crosses the edge of.
    /// - Returns: The text to show.
    func rendered(_ range: NSRange) -> NSAttributedString {
        let shown = NSMutableAttributedString()
        for piece in folds.pieces(of: range) {
            switch piece {
            case .text(let range):
                shown.append(colored.attributedSubstring(from: range))
            case .fold(let index):
                shown.append(NSAttributedString(string: folds.shown[index].placeholder, attributes: [
                    .font: PredicateSyntax.monospaced(size: textSize), .foregroundColor: NSColor.secondaryLabelColor,
                    .backgroundColor: Self.placeholderBackground, .cursor: NSCursor.pointingHand,
                ]))
            }
        }
        return shown
    }

    // MARK: Selection
    /// Follow the selection: the status bar, the key path bar, the cursor's line and its bracket.
    ///
    /// - Parameter notification: The text view's notification.
    func textViewDidChangeSelection(_ notification: Notification) {
        selectionChanged()
    }

    /// Bring the bars, the cursor's line and the matching bracket up to date with the selection.
    func selectionChanged() {
        guard let textView else { return }
        let shown = textView.selectedRange()
        let selection = folds.original(shown)
        let caret = min(selection.location, original.length)
        caretLine = lines.line(at: caret)
        let start = lines.starts[caretLine]
        let column = characterCount(NSRange(location: start, length: caret - start)) + 1
        let selected = characterCount(selection)
        let path = readsKeyPaths ? keyPath(at: caret) : []
        let line = caretLine + 1
        publish { controller in
            let status = controller.status
            if status.line != line { status.line = line }
            if status.column != column { status.column = column }
            if status.selected != selected { status.selected = selected }
            if status.keyPath != path { status.keyPath = path }
        }
        highlightBrackets(at: shown.length == 0 ? caret : nil)
        textView.setNeedsDisplay(textView.visibleRect)
        gutter?.needsDisplay = true
    }

    /// Ranges longer than this many UTF-16 units are counted in units, so a long line or selection costs nothing.
    private static let countLimit = 10_000

    /// - Parameter range: A range of the text.
    /// - Returns: How many characters it holds, or its UTF-16 length past ``countLimit``.
    private func characterCount(_ range: NSRange) -> Int {
        range.length > Self.countLimit ? range.length : original.substring(with: range).count
    }

    /// - Parameter offset: An offset in the text.
    /// - Returns: The keys to the value there, none outside the record's values.
    private func keyPath(at offset: Int) -> [String] {
        guard let outline, let index = outline.value(at: offset) else { return [] }
        let path = outline.values[index].keyPath
        return path.isEmpty ? [] : path.components(separatedBy: ".")
    }

    /// Highlight the bracket at the cursor, or just before it, and the bracket matching it. JSON's come from its
    /// outline, so a bracket in a string has none. Neither is highlighted when either is folded away.
    ///
    /// - Parameter caret: Where the cursor is in the text, or `nil` while text is selected.
    private func highlightBrackets(at caret: Int?) {
        clearBrackets()
        guard let caret, let layoutManager = textView?.layoutManager else { return }
        for offset in [caret, caret - 1] where offset >= 0 && offset < original.length {
            let match = outline.map { $0.matchingBracket(at: offset) } ?? TextBrackets.match(at: offset, in: original)
            guard let match else { continue }
            guard folds.fold(hiding: offset) == nil, folds.fold(hiding: match) == nil else { return }
            brackets = [offset, match].map { NSRange(location: folds.shown($0), length: 1) }
            for range in brackets {
                layoutManager.addTemporaryAttribute(.backgroundColor, value: Self.bracketBackground,
                                                    forCharacterRange: range)
            }
            return
        }
    }

    /// Stop highlighting the brackets, as before the text shown changes and would move them.
    func clearBrackets() {
        guard let layoutManager = textView?.layoutManager else { return }
        for range in brackets where NSMaxRange(range) <= layoutManager.textStorage?.length ?? 0 {
            layoutManager.removeTemporaryAttribute(.backgroundColor, forCharacterRange: range)
        }
        brackets = []
    }

    /// - Parameter offset: An offset in the text shown.
    /// - Returns: The line of the text it's on, from 0.
    func line(atShown offset: Int) -> Int {
        lines.line(at: folds.original(offset))
    }

    /// Change what the bars show after the view update that caused the change, as SwiftUI asks.
    ///
    /// - Parameter change: Sets the published values.
    func publish(_ change: @escaping (ReadOnlyTextController) -> Void) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            change(self)
        }
    }

    /// - Parameter isFolded: Is anything folded now?
    func noteFolded(_ isFolded: Bool) {
        publish { if $0.isFolded != isFolded { $0.isFolded = isFolded } }
    }
}
