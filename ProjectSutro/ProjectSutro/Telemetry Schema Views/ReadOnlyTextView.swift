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
/// numbers, and colored for its language as Xcode colors code (ReadOnlyTextView+Syntax.swift).
///
/// SwiftUI's `Text` lays out all of its string at once, which is slow for the telemetry schema's hundred-odd kilobytes;
/// `NSTextView` lays out what's on screen.
struct ReadOnlyTextView: NSViewRepresentable {
    /// What the text is, for its colors.
    enum Language {
        case plain, json, shell, python, javascript, applescript, ruby, perl, xml
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
        language.color(storage)
        storage.endEditing()
    }
}
