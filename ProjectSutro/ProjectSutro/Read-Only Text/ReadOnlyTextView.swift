//
//  ReadOnlyTextView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
import AppKit


// MARK: - Read-only text
/// Long text to read, select, and search with ⌘F: monospaced in a scrolling AppKit text view (``CodeTextView``), with
/// line numbers and fold triangles (``EditorGutter``), and colored for its language as Xcode colors code
/// (ReadOnlyTextView+Syntax.swift). Its ``ReadOnlyTextController`` shows the text and folds it.
///
/// SwiftUI's `Text` lays out all of its string at once, which is slow for the telemetry schema's hundred-odd kilobytes.
/// `NSTextView` lays out what's on screen.
struct ReadOnlyTextView: NSViewRepresentable {
    /// What the text is, for its colors, named as the status bar names it.
    enum Language: String {
        case plain = "Plain Text", json = "JSON", shell = "Shell", python = "Python", javascript = "JavaScript"
        case applescript = "AppleScript", ruby = "Ruby", perl = "Perl", xml = "XML", yara = "YARA"
    }

    /// The text shown.
    let text: String
    var language: Language = .plain
    /// Does right-clicking a value offer its key path and predicate, for an event's record?
    var readsKeyPaths = false
    let controller: ReadOnlyTextController
    @AppStorage(EditorPreferences.wrapsLinesKey) private var wrapsLines = true
    @AppStorage(EditorPreferences.textSizeKey) private var textSize = EditorPreferences.defaultSize

    /// A scroll view around a text view that can't be edited, with the gutter as its ruler.
    ///
    /// - Parameter context: The representable's context.
    /// - Returns: The scroll view.
    func makeNSView(context: Context) -> NSScrollView {
        let scrollView = NSScrollView()
        scrollView.hasVerticalScroller = true
        scrollView.borderType = .noBorder
        scrollView.backgroundColor = .textBackgroundColor
        /// TextKit 1, which the gutter and the folds read.
        let textView = CodeTextView(usingTextLayoutManager: false)
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
        /// Only what's on screen is laid out, so a long text opens and scrolls at once.
        textView.layoutManager?.allowsNonContiguousLayout = true
        scrollView.documentView = textView
        let gutter = EditorGutter(textView: textView)
        scrollView.verticalRulerView = gutter
        scrollView.hasVerticalRuler = true
        scrollView.rulersVisible = true
        /// The text starts under the window's header, not its title bar.
        scrollView.automaticallyAdjustsContentInsets = false
        /// Views stopped clipping to their bounds in macOS 14. The gutter's line drew up through the header.
        if #available(macOS 14.0, *) {
            scrollView.clipsToBounds = true
            gutter.clipsToBounds = true
        }
        controller.attach(textView, gutter: gutter)
        update(controller)
        return scrollView
    }

    /// Show the text if it changed, which keeps the scroll position, selection and folds while it doesn't, and the
    /// text size and wrapping set in any read-only text view.
    ///
    /// - Parameters:
    ///   - scrollView: The scroll view ``makeNSView(context:)`` made.
    ///   - context: The representable's context.
    func updateNSView(_ scrollView: NSScrollView, context: Context) {
        update(controller)
    }

    /// Hand the controller what this view shows, the size first so a new text is colored once.
    ///
    /// - Parameter controller: The text's controller.
    private func update(_ controller: ReadOnlyTextController) {
        controller.readsKeyPaths = readsKeyPaths
        controller.apply(textSize: CGFloat(textSize), wrapsLines: wrapsLines)
        controller.show(text, language: language)
    }
}
