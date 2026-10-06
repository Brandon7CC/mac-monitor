//
//  ReadOnlyTextView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
import AppKit


// MARK: - Read-only text
/// Long text to read, select, and search with ⌘F: monospaced, in a scrolling AppKit text view.
///
/// SwiftUI's `Text` lays out all of its string at once, which is slow for the telemetry schema's hundred-odd kilobytes;
/// `NSTextView` lays out what's on screen.
struct ReadOnlyTextView: NSViewRepresentable {
    /// The text shown.
    let text: String
    
    /// A scroll view around a text view that can't be edited.
    ///
    /// - Parameter context: The representable's context.
    /// - Returns: The scroll view.
    func makeNSView(context: Context) -> NSScrollView {
        let scrollView = NSTextView.scrollableTextView()
        if let textView = scrollView.documentView as? NSTextView {
            textView.isEditable = false
            textView.isSelectable = true
            textView.isRichText = false
            textView.usesFindBar = true
            textView.isIncrementalSearchingEnabled = true
            textView.textContainerInset = NSSize(width: 6, height: 8)
            show(text, in: textView)
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
    }
    
    /// Replace a text view's text, in the monospaced font.
    ///
    /// - Parameters:
    ///   - text: The text.
    ///   - textView: The text view.
    private func show(_ text: String, in textView: NSTextView) {
        textView.string = text
        textView.font = .monospacedSystemFont(ofSize: NSFont.smallSystemFontSize, weight: .regular)
    }
}
