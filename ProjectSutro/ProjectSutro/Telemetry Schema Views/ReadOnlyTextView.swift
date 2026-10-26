//
//  ReadOnlyTextView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
import AppKit


// MARK: - Read-only text
/// Long text to read, select, and search with ⌘F: monospaced and wrapped in a scrolling AppKit text view, with line
/// numbers, and JSON colored as Xcode colors it (``PredicateSyntax``'s colors).
///
/// SwiftUI's `Text` lays out all of its string at once, which is slow for the telemetry schema's hundred-odd kilobytes;
/// `NSTextView` lays out what's on screen.
struct ReadOnlyTextView: NSViewRepresentable {
    /// What the text is, for its colors.
    enum Language {
        case plain, json
    }

    /// The text shown.
    let text: String
    var language: Language = .plain

    /// A scroll view around a text view that can't be edited.
    ///
    /// - Parameter context: The representable's context.
    /// - Returns: The scroll view.
    func makeNSView(context: Context) -> NSScrollView {
        let scrollView = NSScrollView()
        scrollView.hasVerticalScroller = true
        scrollView.borderType = .noBorder
        /// TextKit 1, which the line numbers read.
        let textView = NSTextView(usingTextLayoutManager: false)
        textView.isEditable = false
        textView.isSelectable = true
        textView.isRichText = false
        textView.usesFindBar = true
        textView.isIncrementalSearchingEnabled = true
        textView.backgroundColor = .textBackgroundColor
        textView.textContainerInset = NSSize(width: 6, height: 8)
        textView.isVerticallyResizable = true
        textView.autoresizingMask = [.width]
        textView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        textView.textContainer?.widthTracksTextView = true
        scrollView.documentView = textView
        show(text, in: textView)
        scrollView.verticalRulerView = LineNumberRuler(textView: textView)
        scrollView.hasVerticalRuler = true
        scrollView.rulersVisible = true
        /// The text starts under the window's header, not its title bar.
        scrollView.automaticallyAdjustsContentInsets = false
        /// Views stopped clipping to their bounds in macOS 14. The gutter's line drew up through the header.
        if #available(macOS 14.0, *) {
            scrollView.clipsToBounds = true
            scrollView.verticalRulerView?.clipsToBounds = true
        }
        return scrollView
    }

    /// Show the text if it changed, which keeps the scroll position and selection while it doesn't.
    ///
    /// - Parameters:
    ///   - scrollView: The scroll view ``makeNSView(context:)`` made.
    ///   - context: The representable's context.
    func updateNSView(_ scrollView: NSScrollView, context: Context) {
        guard let textView = scrollView.documentView as? NSTextView, textView.string != text else { return }
        show(text, in: textView)
        textView.scrollToBeginningOfDocument(nil)
        scrollView.verticalRulerView?.needsDisplay = true
    }

    /// Replace a text view's text, in the monospaced font, colored for its language.
    ///
    /// - Parameters:
    ///   - text: The text.
    ///   - textView: The text view.
    private func show(_ text: String, in textView: NSTextView) {
        textView.string = text
        guard let storage = textView.textStorage else { return }
        storage.beginEditing()
        storage.setAttributes([.font: PredicateSyntax.font, .foregroundColor: NSColor.textColor],
                              range: NSRange(location: 0, length: storage.length))
        if language == .json { Self.colorJSON(storage) }
        storage.endEditing()
    }

    /// A JSON token: a string and whether a colon follows it (a key), a literal, or a number.
    private static let jsonToken = try! NSRegularExpression(
        pattern: #"("(?:[^"\\]|\\.)*")(\s*:)?|\b(true|false|null)\b|-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b"#)

    /// Color JSON's keys, strings, literals and numbers.
    ///
    /// - Parameter storage: The text.
    private static func colorJSON(_ storage: NSTextStorage) {
        let range = NSRange(location: 0, length: storage.length)
        for match in jsonToken.matches(in: storage.string, range: range) {
            if match.range(at: 1).location != NSNotFound {
                let color = match.range(at: 2).location != NSNotFound ? PredicateSyntax.keyColor
                    : PredicateSyntax.stringColor
                storage.addAttribute(.foregroundColor, value: color, range: match.range(at: 1))
            } else if match.range(at: 3).location != NSNotFound {
                storage.addAttributes([.foregroundColor: PredicateSyntax.keywordColor, .font: PredicateSyntax.boldFont],
                                      range: match.range)
            } else {
                storage.addAttribute(.foregroundColor, value: PredicateSyntax.numberColor, range: match.range)
            }
        }
    }
}
