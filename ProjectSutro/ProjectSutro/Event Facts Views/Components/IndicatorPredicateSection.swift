//
//  IndicatorPredicateSection.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/8/26.
//

import SwiftUI
import AppKit
import SutroESFramework


// MARK: - Predicate section
/// An indicator's predicate in the Indicators popover: a Predicate disclosure, closed to start, that shows it laid out
/// a condition a line (``PredicateLayout``), colored and selectable, and beside it Copy, which puts it on the
/// pasteboard exactly as stored, on one line, and tells VoiceOver it did.
struct IndicatorPredicateSection: View {
    let indicator: Indicator
    @State private var isOpen = false
    /// How many times Copy was clicked, so only the last click's "Copied" goes back to "Copy".
    @State private var copies = 0
    /// Does Copy say "Copied"?
    @State private var showsCopied = false

    /// How long Copy says "Copied", in seconds.
    private static let copiedDuration = 1.6

    var body: some View {
        let layout = PredicateLayout(indicator.predicate)
        VStack(alignment: .leading, spacing: 8) {
            Divider()
            HStack(spacing: 8) {
                disclosure
                Spacer(minLength: 0)
                copyButton(layout)
            }
            if isOpen {
                LaidOutPredicateView(layout: layout, name: indicator.name)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Self.panel, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            }
        }
    }

    /// The panel behind the predicate, a shade darker than the popover.
    private static let panel = Color.appearance(light: .black.withAlphaComponent(0.05),
                                                dark: .black.withAlphaComponent(0.18))

    /// Predicate, with a chevron that turns down while it's open.
    private var disclosure: some View {
        Button {
            withAnimation(.easeOut(duration: 0.15)) { isOpen.toggle() }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 9, weight: .bold)).foregroundStyle(.secondary)
                    .rotationEffect(.degrees(isOpen ? 90 : 0))
                Text("Predicate").font(.system(size: 13, weight: .semibold))
            }
            .frame(minHeight: 24)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Predicate")
        .accessibilityValue(isOpen ? "Shown" : "Hidden")
        .accessibilityHint(isOpen ? "Hides the predicate" : "Shows the predicate")
    }

    /// - Parameter layout: The predicate, laid out.
    /// - Returns: Copy, in the accent color, or a green check and "Copied" for a moment after it's clicked.
    private func copyButton(_ layout: PredicateLayout) -> some View {
        Button {
            Self.copy(layout.oneLine, announcing: "Copied the \(indicator.name) predicate")
            copies += 1
            showsCopied = true
            let copy = copies
            DispatchQueue.main.asyncAfter(deadline: .now() + Self.copiedDuration) {
                if copies == copy { showsCopied = false }
            }
        } label: {
            HStack(spacing: 4) {
                Image(systemName: showsCopied ? "checkmark" : "doc.on.doc")
                    .font(.system(size: 11, weight: showsCopied ? .bold : .regular))
                    .foregroundStyle(showsCopied ? Color.green : Color.accentColor)
                Text(showsCopied ? "Copied" : "Copy")
            }
            .font(.system(size: 12))
            .foregroundStyle(Color.accentColor)
            .frame(minHeight: 24)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Copies the predicate exactly as stored, on one line")
        .accessibilityLabel("Copy the \(indicator.name) predicate")
    }

    /// Put text on the pasteboard and have VoiceOver say so.
    ///
    /// - Parameters:
    ///   - text: The text.
    ///   - announcement: What VoiceOver says.
    private static func copy(_ text: String, announcing announcement: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested,
                             userInfo: [.announcement: announcement,
                                        .priority: NSAccessibilityPriorityLevel.high.rawValue])
    }
}


// MARK: - Laid-out predicate
/// A laid-out predicate to read and select, in a text view that doesn't scroll: monospaced and colored as the
/// predicate editor colors a predicate (``PredicateSyntax``), in light and dark. Each line wraps two characters in
/// from where it starts, so a wrapped condition reads as one.
struct LaidOutPredicateView: NSViewRepresentable {
    let layout: PredicateLayout
    /// The indicator's name, for VoiceOver.
    let name: String

    /// The text's size, in points.
    static let fontSize: CGFloat = 11
    /// Each line's height, in points.
    static let lineHeight: CGFloat = 16

    /// - Parameter context: The representable's context.
    /// - Returns: A text view that can be selected but not edited, without a background or margins.
    func makeNSView(context: Context) -> NSTextView {
        /// TextKit 1, whose layout manager measures the text's height.
        let textView = NSTextView(usingTextLayoutManager: false)
        textView.isEditable = false
        textView.isSelectable = true
        textView.isRichText = false
        textView.drawsBackground = false
        textView.textContainerInset = .zero
        textView.textContainer?.lineFragmentPadding = 0
        textView.textContainer?.widthTracksTextView = true
        show(in: textView)
        return textView
    }

    /// Show the predicate again if it changed.
    ///
    /// - Parameters:
    ///   - textView: The text view ``makeNSView(context:)`` made.
    ///   - context: The representable's context.
    func updateNSView(_ textView: NSTextView, context: Context) {
        if textView.string != layout.text { show(in: textView) }
    }

    /// - Parameters:
    ///   - proposal: The width offered.
    ///   - textView: The text view.
    ///   - context: The representable's context.
    /// - Returns: The width offered, and the height of the text wrapped to it.
    func sizeThatFits(_ proposal: ProposedViewSize, nsView textView: NSTextView, context: Context) -> CGSize? {
        guard let container = textView.textContainer, let manager = textView.layoutManager else { return nil }
        let width = proposal.width.flatMap { $0.isFinite ? $0 : nil } ?? IndicatorsPopover.width
        container.containerSize = NSSize(width: width, height: .greatestFiniteMagnitude)
        manager.ensureLayout(for: container)
        return CGSize(width: width, height: ceil(manager.usedRect(for: container).height))
    }

    /// Show the laid-out predicate: colored, each line indented as deep as it is, and wrapping two characters further.
    ///
    /// - Parameter textView: The text view.
    private func show(in textView: NSTextView) {
        textView.string = layout.text
        textView.setAccessibilityLabel("\(name) predicate")
        guard let storage = textView.textStorage else { return }
        PredicateSyntax.highlight(storage, size: Self.fontSize)
        let font = PredicateSyntax.monospaced(size: Self.fontSize)
        let space = (" " as NSString).size(withAttributes: [.font: font]).width
        var location = 0
        storage.beginEditing()
        for line in layout.lines {
            let lead = line.depth * PredicateLayout.indentWidth
            let length = lead + (line.text as NSString).length
            let style = NSMutableParagraphStyle()
            style.headIndent = CGFloat(lead + 2) * space
            style.minimumLineHeight = Self.lineHeight
            style.maximumLineHeight = Self.lineHeight
            /// The line, and its line break.
            let range = NSRange(location: location, length: min(length + 1, storage.length - location))
            storage.addAttribute(.paragraphStyle, value: style, range: range)
            location += length + 1
        }
        storage.endEditing()
    }
}
