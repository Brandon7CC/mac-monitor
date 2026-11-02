//
//  PredicateCompletion.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/25/26.
//

import SwiftUI
import AppKit
import SutroESFramework


// MARK: - Completing text view
/// The predicate editor's text view, which completes the word being typed as Xcode does: a list under the cursor of
/// what completes it (``PredicateText/completions(in:at:)``), the rest of the chosen one in grey after the cursor,
/// the Up and Down Arrow keys to choose, Tab or Return to take one, and Escape to put the list away until the next
/// keystroke.
final class CompletingTextView: NSTextView {
    private var completion: PredicateText.Completion?
    private var selected = 0
    /// Escape put the list away: it stays away until the text changes.
    private var dismissed = false
    /// Is SwiftUI setting the text (``setText(_:)``)? The list neither shows nor hides then.
    private var isSettingText = false
    /// The list's panel, once it has shown. Hiding never makes one: SwiftUI sets the text while it builds the view, and
    /// macOS 13 aborts when a new panel's hosting view lays out then.
    private var loadedPanel: CompletionPanel?
    private var panel: CompletionPanel {
        if let loadedPanel { return loadedPanel }
        let made = CompletionPanel()
        loadedPanel = made
        return made
    }
    /// Is the list showing?
    private var isListShowing: Bool { loadedPanel?.isVisible == true }

    /// The rest of the chosen completion, drawn in grey after the cursor, when the cursor ends the word.
    private var ghost: String? {
        guard let completion, isListShowing, completion.items.indices.contains(selected) else { return nil }
        let typed = (string as NSString).substring(with: completion.range), word = completion.items[selected].word
        let caret = selectedRange().location, text = string as NSString
        let next = caret < text.length ? text.substring(with: NSRange(location: caret, length: 1)) : " "
        guard word.hasPrefix(typed), word.count > typed.count, " \t\n),".contains(next) else { return nil }
        return String(word.dropFirst(typed.count))
    }

    override func didChangeText() {
        super.didChangeText()
        dismissed = false
        refreshCompletion()
    }

    override func setSelectedRanges(_ ranges: [NSValue], affinity: NSSelectionAffinity,
                                    stillSelecting stillSelectingFlag: Bool) {
        super.setSelectedRanges(ranges, affinity: affinity, stillSelecting: stillSelectingFlag)
        if !stillSelectingFlag && !isSettingText { refreshCompletion() }
    }

    /// Replace the text and color its syntax, as SwiftUI does from the binding. A list left showing goes away after
    /// the update.
    ///
    /// - Parameter text: The new text.
    func setText(_ text: String) {
        isSettingText = true
        string = text
        if let textStorage { PredicateSyntax.highlight(textStorage) }
        isSettingText = false
        guard completion != nil else { return }
        DispatchQueue.main.async { [weak self] in self?.hideCompletion() }
    }

    override func resignFirstResponder() -> Bool {
        hideCompletion()
        return super.resignFirstResponder()
    }

    override func viewWillMove(toWindow newWindow: NSWindow?) {
        if newWindow == nil { hideCompletion() }
        super.viewWillMove(toWindow: newWindow)
    }

    /// The list's keys while it shows: Up Arrow, Down Arrow, Tab, Return and Escape. Tab with the list away brings it
    /// back.
    override func doCommand(by selector: Selector) {
        if isListShowing, let completion, !completion.items.isEmpty {
            switch selector {
            case #selector(moveDown(_:)):
                selected = (selected + 1) % completion.items.count
                return showCompletion()
            case #selector(moveUp(_:)):
                selected = (selected + completion.items.count - 1) % completion.items.count
                return showCompletion()
            case #selector(insertTab(_:)), #selector(insertNewline(_:)):
                return accept(selected)
            case #selector(cancelOperation(_:)):
                dismissed = true
                return hideCompletion()
            default:
                break
            }
        } else if selector == #selector(insertTab(_:)) || selector == #selector(cancelOperation(_:)),
                  selectedRange().length == 0,
                  PredicateText.completions(in: string, at: selectedRange().location) != nil {
            dismissed = false
            return refreshCompletion(evenEmpty: true)
        }
        super.doCommand(by: selector)
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        guard let ghost, let window else { return }
        let caret = convert(window.convertFromScreen(firstRect(forCharacterRange: selectedRange(), actualRange: nil)),
                            from: nil)
        let attributes: [NSAttributedString.Key: Any] = [.font: PredicateSyntax.font,
                                                         .foregroundColor: NSColor.tertiaryLabelColor]
        (ghost as NSString).draw(at: NSPoint(x: caret.minX, y: caret.minY), withAttributes: attributes)
    }

    /// Show the list for the word before the cursor, or put it away when nothing completes it.
    ///
    /// - Parameter evenEmpty: Show it for a word that's only begun, such as an opening quote, as Tab asks.
    private func refreshCompletion(evenEmpty: Bool = false) {
        let caret = selectedRange()
        guard caret.length == 0, !dismissed, window != nil,
              let found = PredicateText.completions(in: string, at: caret.location),
              evenEmpty || found.range.length > 0 else { return hideCompletion() }
        if completion?.range.location != found.range.location || completion?.items.first != found.items.first {
            selected = 0
        }
        completion = found
        selected = min(selected, found.items.count - 1)
        showCompletion()
    }

    private func showCompletion() {
        guard let completion, let window else { return }
        let typed = (string as NSString).substring(with: completion.range)
        let line = firstRect(forCharacterRange: NSRange(location: completion.range.location, length: 0),
                             actualRange: nil)
        panel.show(completion.items, selected: selected, typed: typed, below: line, in: window) { [weak self] index in
            self?.accept(index)
        }
        needsDisplay = true
    }

    private func hideCompletion() {
        guard isListShowing || completion != nil else { return }
        loadedPanel?.hide()
        completion = nil
        needsDisplay = true
    }

    /// Replace the word with a completion, undoably.
    ///
    /// - Parameter index: The completion's place in the list.
    private func accept(_ index: Int) {
        guard let completion, completion.items.indices.contains(index) else { return }
        let word = completion.items[index].word
        hideCompletion()
        if shouldChangeText(in: completion.range, replacementString: word) {
            replaceCharacters(in: completion.range, with: word)
            didChangeText()
        }
    }
}


// MARK: - The list
/// The completions' floating list, under the word being completed. It never takes the keyboard: the text view keeps
/// typing, and tells it what to show.
private final class CompletionPanel: NSPanel {
    private let host = NSHostingView(rootView: CompletionList(items: [], selected: 0, typed: "") { _ in })

    init() {
        super.init(contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: true)
        isFloatingPanel = true
        hidesOnDeactivate = true
        hasShadow = true
        isOpaque = false
        backgroundColor = .clear
        contentView = host
    }

    override var canBecomeKey: Bool { false }
    override var canBecomeMain: Bool { false }

    /// - Parameters:
    ///   - items: The completions.
    ///   - selected: The chosen one.
    ///   - typed: The word typed.
    ///   - line: Where the word starts, in screen coordinates.
    ///   - parent: The text view's window.
    ///   - choose: Takes a completion clicked.
    func show(_ items: [PredicateText.Completion.Item], selected: Int, typed: String, below line: NSRect,
              in parent: NSWindow, choose: @escaping (Int) -> Void) {
        host.rootView = CompletionList(items: items, selected: selected, typed: typed, choose: choose)
        let size = host.fittingSize
        setFrame(NSRect(x: line.minX - 28, y: line.minY - size.height - 4, width: size.width, height: size.height),
                 display: true)
        if parent.childWindows?.contains(self) != true { parent.addChildWindow(self, ordered: .above) }
        orderFront(nil)
    }

    func hide() {
        parent?.removeChildWindow(self)
        orderOut(nil)
    }
}


/// The completions, the chosen one's type and what the schema says of it, and the keys that take one.
private struct CompletionList: View {
    let items: [PredicateText.Completion.Item]
    let selected: Int
    let typed: String
    let choose: (Int) -> Void

    /// The most rows shown at once, around the chosen one.
    private static let visible = 8

    var body: some View {
        let start = max(0, min(selected - Self.visible / 2, items.count - Self.visible))
        let shown = Array(items.indices.dropFirst(start).prefix(Self.visible))
        VStack(alignment: .leading, spacing: 0) {
            VStack(spacing: 1) {
                ForEach(shown, id: \.self) { index in
                    row(items[index], isSelected: index == selected)
                        .contentShape(Rectangle())
                        .onTapGesture { choose(index) }
                }
            }
            .padding(4)
            if items.indices.contains(selected) {
                footer(items[selected])
            }
        }
        .frame(width: 400)
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color(nsColor: .separatorColor)))
    }

    /// - Parameters:
    ///   - item: A completion.
    ///   - isSelected: Is it the chosen one?
    /// - Returns: Its badge, its name with what's typed in bold, and its type.
    private func row(_ item: PredicateText.Completion.Item, isSelected: Bool) -> some View {
        let (bold, rest) = Self.split(item.word, typed: typed)
        return HStack(spacing: 8) {
            CompletionBadge(kind: item.kind)
            (Text(bold).bold() + Text(rest))
                .font(.system(size: 12, design: .monospaced))
                .lineLimit(1).truncationMode(.middle)
            Spacer(minLength: 8)
            Text(item.type).font(.caption).foregroundStyle(isSelected ? .white.opacity(0.85) : .secondary)
        }
        .foregroundStyle(isSelected ? .white : .primary)
        .padding(.horizontal, 8)
        .frame(height: 22)
        .background(isSelected ? Color.accentColor : .clear, in: RoundedRectangle(cornerRadius: 5))
    }

    /// - Parameter item: The chosen completion.
    /// - Returns: Its whole word and type, what the schema says of it, and the keys.
    private func footer(_ item: PredicateText.Completion.Item) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 4) {
                Text(item.word).font(.system(size: 11, weight: .semibold, design: .monospaced)).lineLimit(1)
                    .truncationMode(.head)
                if !item.type.isEmpty { Text("· \(item.type)").font(.caption).foregroundStyle(.secondary) }
            }
            if let summary = item.summary {
                Text(summary).font(.caption).foregroundStyle(.secondary).lineLimit(3)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text("⇥ completes · ↩ chooses · esc dismisses").font(.caption2).foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.primary.opacity(0.04))
    }

    /// What a row shows of a completion: a key path's last key, after its parent as typed, with what's typed of it
    /// in bold, or a whole key path found by its last key.
    ///
    /// - Parameters:
    ///   - word: The completion.
    ///   - typed: The word typed.
    /// - Returns: The bold part and the rest.
    static func split(_ word: String, typed: String) -> (String, String) {
        guard word.hasPrefix(typed) else { return ("", word) }
        let parent = typed.lastIndex(of: ".").map { typed.index(after: $0) } ?? typed.startIndex
        let shown = word[parent...], fragment = typed[parent...]
        return (String(shown.prefix(fragment.count)), String(shown.dropFirst(fragment.count)))
    }
}


// MARK: - Badges
/// What a completion or a library row is, as Xcode badges its completions: K a key, R related events, W a keyword,
/// V a value, S a saved predicate, and a clock a recent one.
struct CompletionBadge: View {
    enum Kind {
        case key, related, keyword, value, saved, recent
    }

    let kind: Kind

    /// - Parameter kind: A completion's kind.
    init(kind: PredicateText.Completion.Item.Kind) {
        switch kind {
        case .key: self.kind = .key
        case .related: self.kind = .related
        case .keyword: self.kind = .keyword
        case .value: self.kind = .value
        }
    }

    /// - Parameter kind: A library row's kind.
    init(_ kind: Kind) {
        self.kind = kind
    }

    var body: some View {
        Group {
            if kind == .recent {
                Image(systemName: "clock").font(.system(size: 9, weight: .bold))
            } else {
                Text(letter).font(.system(size: 10, weight: .bold))
            }
        }
        .foregroundStyle(.white)
        .frame(width: 16, height: 16)
        .background(color, in: RoundedRectangle(cornerRadius: 4))
        .accessibilityHidden(true)
    }

    private var letter: String {
        switch kind {
        case .key: return "K"
        case .related: return "R"
        case .keyword: return "W"
        case .value: return "V"
        case .saved: return "S"
        case .recent: return ""
        }
    }

    private var color: Color {
        switch kind {
        case .key: return Color(nsColor: PredicateSyntax.keyColor)
        case .related: return Color(nsColor: PredicateSyntax.variableColor)
        case .keyword: return Color(nsColor: PredicateSyntax.keywordColor)
        case .value: return Color(nsColor: PredicateSyntax.stringColor)
        case .saved: return .orange
        case .recent: return .gray
        }
    }
}
