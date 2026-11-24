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
/// pasteboard exactly as stored, on one line, and tells VoiceOver it did. A sequence's is a Sequence disclosure with
/// each step's predicate under its name, and Copy puts the whole sequence on the pasteboard, a step a line.
///
/// The lines the event passed are marked (``PredicateLayout/passedLines(by:eventType:isWholeRule:)``), when its hit
/// says why it matched.
struct IndicatorPredicateSection: View {
    let indicator: Indicator
    /// Why the event matched the indicator, when its hit says.
    var match: IndicatorMatch?
    @State private var isOpen = false
    /// How many times Copy was clicked, so only the last click's "Copied" goes back to "Copy".
    @State private var copies = 0
    /// Does Copy say "Copied"?
    @State private var showsCopied = false

    /// How long Copy says "Copied", in seconds.
    private static let copiedDuration = 1.6

    var body: some View {
        let layouts = indicator.rule.predicates.map { (step: $0.step, layout: PredicateLayout($0.predicate)) }
        VStack(alignment: .leading, spacing: 8) {
            Divider()
            HStack(spacing: 8) {
                disclosure
                Spacer(minLength: 0)
                copyButton(layouts.count == 1 ? layouts[0].layout.oneLine : indicator.rule.text)
            }
            if isOpen {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(layouts.indices, id: \.self) { index in
                        if let step = layouts[index].step {
                            Text(step).font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
                        }
                        LaidOutPredicateView(layout: layouts[index].layout, name: indicator.name,
                                             passed: passed(layouts[index].layout))
                    }
                }
                    .padding(.vertical, 8)
                    .padding(.horizontal, 8 - LaidOutPredicateView.linePadding)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Self.panel, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            }
        }
    }

    /// The panel behind the predicate and behind a matched value, a shade darker than the popover.
    static let panel = Color.appearance(light: .black.withAlphaComponent(0.05),
                                        dark: .black.withAlphaComponent(0.18))

    /// - Parameter layout: A laid-out predicate of the indicator's.
    /// - Returns: The lines the event passed, or none when its hit doesn't say why it matched. A sequence's step may
    ///   be one another event passed, so only what the hit lists marks its lines.
    private func passed(_ layout: PredicateLayout) -> IndexSet {
        match.map {
            layout.passedLines(by: $0.fields, eventType: $0.eventType, isWholeRule: indicator.sequence == nil)
        } ?? []
    }

    /// Predicate, with a chevron that turns down while it's open.
    private var disclosure: some View {
        Button {
            withAnimation(.easeOut(duration: 0.15)) { isOpen.toggle() }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 9, weight: .bold)).foregroundStyle(.secondary)
                    .rotationEffect(.degrees(isOpen ? 90 : 0))
                Text(title).font(.system(size: 13, weight: .semibold))
            }
            .frame(minHeight: 24)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(title)
        .accessibilityValue(isOpen ? "Shown" : "Hidden")
        .accessibilityHint(isOpen ? "Hides the \(noun)" : "Shows the \(noun)")
    }

    /// The disclosure's title: Predicate, or Sequence for a sequence.
    private var title: String { indicator.sequence == nil ? "Predicate" : "Sequence" }

    /// What the disclosure shows, in a sentence: the predicate, or the sequence.
    private var noun: String { title.lowercased() }

    /// - Parameter text: The rule, as Copy puts it on the pasteboard.
    /// - Returns: Copy, in the accent color, or a green check and "Copied" for a moment after it's clicked.
    private func copyButton(_ text: String) -> some View {
        Button {
            Self.copy(text, announcing: "Copied the \(indicator.name) \(noun)")
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
        .help(indicator.sequence == nil ? "Copies the predicate exactly as stored, on one line"
              : "Copies the sequence, a step a line")
        .accessibilityLabel("Copy the \(indicator.name) \(noun)")
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
/// from where it starts, so a wrapped condition reads as one. A line the event passed has a yellow mark behind its
/// text.
struct LaidOutPredicateView: NSViewRepresentable {
    let layout: PredicateLayout
    /// The indicator's name, for VoiceOver.
    let name: String
    /// The lines the event passed, by their place in the layout.
    var passed: IndexSet = []

    /// The text's size, in points.
    static let fontSize: CGFloat = 11
    /// Each line's height, in points.
    static let lineHeight: CGFloat = 16
    /// The room at each end of a line, in points, which a mark reaches into.
    static let linePadding: CGFloat = 3
    /// The mark behind a line the event passed, in light and dark.
    private static let mark = NSColor.appearance(light: .systemYellow.withAlphaComponent(0.34),
                                                 dark: .systemYellow.withAlphaComponent(0.26))

    /// Remembers the lines marked, so they're marked again only when they change.
    final class Coordinator {
        var passed: IndexSet = []
    }

    /// - Returns: The view's coordinator.
    func makeCoordinator() -> Coordinator { Coordinator() }

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
        textView.textContainer?.replaceLayoutManager(MarkLayoutManager())
        textView.textContainer?.lineFragmentPadding = Self.linePadding
        textView.textContainer?.widthTracksTextView = true
        show(in: textView)
        context.coordinator.passed = passed
        return textView
    }

    /// Show the predicate again if it, or the lines the event passed, changed.
    ///
    /// - Parameters:
    ///   - textView: The text view ``makeNSView(context:)`` made.
    ///   - context: The representable's context.
    func updateNSView(_ textView: NSTextView, context: Context) {
        guard textView.string != layout.text || context.coordinator.passed != passed else { return }
        show(in: textView)
        context.coordinator.passed = passed
    }

    /// - Parameters:
    ///   - proposal: The width offered.
    ///   - textView: The text view.
    ///   - context: The representable's context.
    /// - Returns: The width offered, and the height of the text wrapped to it.
    func sizeThatFits(_ proposal: ProposedViewSize, nsView textView: NSTextView, context: Context) -> CGSize? {
        guard let storage = textView.textStorage else { return nil }
        let width = proposal.width.flatMap { $0.isFinite ? $0 : nil } ?? IndicatorsPopover.width
        return CGSize(width: width, height: Self.height(of: storage, wrappedTo: width))
    }

    /// The height of text wrapped to a width, measured apart from the text view. Changing the text view's own
    /// container as SwiftUI measures it asks the popover's window to lay out again each time, and macOS 13 raises an
    /// exception when a window is asked more often than it has views.
    ///
    /// - Parameters:
    ///   - text: The text, with its paragraph styles.
    ///   - width: The width its lines wrap to, in points.
    /// - Returns: Its height, in points.
    private static func height(of text: NSAttributedString, wrappedTo width: CGFloat) -> CGFloat {
        let storage = NSTextStorage(attributedString: text)
        let manager = NSLayoutManager()
        let container = NSTextContainer(size: NSSize(width: width, height: .greatestFiniteMagnitude))
        container.lineFragmentPadding = linePadding
        manager.addTextContainer(container)
        storage.addLayoutManager(manager)
        manager.ensureLayout(for: container)
        return ceil(manager.usedRect(for: container).height)
    }

    /// Show the laid-out predicate: colored, each line indented as deep as it is, and wrapping two characters further,
    /// with a mark behind the text of each line the event passed.
    ///
    /// - Parameter textView: The text view.
    private func show(in textView: NSTextView) {
        textView.string = layout.text
        textView.setAccessibilityLabel("\(name) predicate")
        guard let storage = textView.textStorage else { return }
        PredicateSyntax.highlight(storage, size: Self.fontSize, for: .indicator)
        let font = PredicateSyntax.monospaced(size: Self.fontSize)
        let space = (" " as NSString).size(withAttributes: [.font: font]).width
        var location = 0
        storage.beginEditing()
        for (index, line) in layout.lines.enumerated() {
            let lead = line.depth * PredicateLayout.indentWidth
            let length = lead + (line.text as NSString).length
            if passed.contains(index) {
                storage.addAttribute(.backgroundColor, value: Self.mark,
                                     range: NSRange(location: location + lead, length: length - lead))
            }
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


// MARK: - Marks
/// Draws the mark behind a passed line as a round-cornered box around its text, a little wider than the text, on each
/// line it wraps to. The text view has no inset, so the text container's coordinates are the view's.
private final class MarkLayoutManager: NSLayoutManager {
    /// - Parameters:
    ///   - rectArray: The rectangles behind the text, which reach the line's end where it wraps. They aren't used.
    ///   - rectCount: How many there are.
    ///   - charRange: The characters they're behind.
    ///   - color: The background's color.
    override func fillBackgroundRectArray(_ rectArray: UnsafePointer<NSRect>, count rectCount: Int,
                                          forCharacterRange charRange: NSRange, color: NSColor) {
        color.setFill()
        let glyphs = glyphRange(forCharacterRange: charRange, actualCharacterRange: nil)
        enumerateLineFragments(forGlyphRange: glyphs) { _, _, container, fragment, _ in
            let part = NSIntersectionRange(glyphs, fragment)
            guard part.length > 0 else { return }
            let rect = self.boundingRect(forGlyphRange: part, in: container)
                .insetBy(dx: -LaidOutPredicateView.linePadding, dy: 1)
            NSBezierPath(roundedRect: rect, xRadius: 4, yRadius: 4).fill()
        }
    }
}
