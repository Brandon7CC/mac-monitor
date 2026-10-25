//
//  PredicateEditorPane.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/23/26.
//

import SwiftUI
import AppKit
import SutroESFramework


// MARK: - Predicate editor
/// The pane beside the event tables for writing a predicate on each event's record: a code editor that colors its
/// syntax, completes as it's typed (``CompletingTextView``), marks keys the schema doesn't name and checks it as
/// `macmonitor stream --predicate` does, over one search of the record's keys, related events, and saved and recent
/// predicates to insert. Apply (⌘↩) filters the tables.
struct PredicateEditorPane: View {
    @ObservedObject var search: EventSearchController
    /// The tables' queries, which only the footer follows: they change with every event saved. `nil` with no main
    /// window.
    let model: EventQueryModel?
    /// Is it in its own window rather than beside the tables? Its tools are then the window's toolbar.
    var isWindow = false
    /// Opens the telemetry schema's window.
    let openSchema: () -> Void

    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismiss) private var dismiss

    @StateObject private var editor = PredicateEditorController()

    @State private var libraryQuery = ""
    @State private var naming = false
    @State private var newName = ""

    var body: some View {
        let problem = search.draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? nil : search.problem(with: search.draft)
        VStack(spacing: 0) {
            if !isWindow {
                HStack(spacing: 4) {
                    Spacer()
                    tools
                    Divider().frame(height: 16).padding(.horizontal, 2)
                    Button { search.showsEditor = false } label: { Image(systemName: "xmark") }
                        .help("Close the predicate editor. A predicate applied stays applied.")
                }
                .buttonStyle(.borderless)
                .labelStyle(.iconOnly)
                .padding(.horizontal, 10)
                .frame(height: 32)
                Divider()
            }
            editorBox(problem: problem)
                .padding(12)
            SettingsSearchField(text: $libraryQuery, prompt: "Keys, related events and predicates")
                .padding(.horizontal, 12)
                .padding(.bottom, 6)
            PredicateLibraryList(query: libraryQuery, saved: search.saved, recents: search.recents, editor: editor,
                                 load: { search.draft = $0 }, delete: { search.delete($0) })
                .equatable()
            Divider()
            if let model {
                PredicateEditorFooter(search: search, model: model, problem: problem)
            }
        }
        .frame(minWidth: 340)
        .modifier(WindowToolbar(isWindow: isWindow) { tools.labelStyle(.iconOnly) })
        .alert("Save Predicate", isPresented: $naming) {
            TextField("Name", text: $newName)
            Button("Save") {
                let name = newName.trimmingCharacters(in: .whitespaces)
                if !name.isEmpty { search.save(name, source: search.draft) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Saved predicates are listed under Saved, and found by name.")
        }
    }

    // MARK: Tools
    /// Format, Save, Copy, the schema, and Pop Out or Dock: the pane's header, or its window's toolbar.
    @ViewBuilder private var tools: some View {
        Button { search.draft = Self.formatted(search.draft) } label: {
            Label("Format", systemImage: "text.alignleft")
        }
        .help("Put each AND and OR on its own line")
        Button { newName = ""; naming = true } label: { Label("Save…", systemImage: "star") }
            .disabled(search.draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            .help("Keep this predicate under Saved")
        Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(search.draft, forType: .string)
        } label: { Label("Copy", systemImage: "doc.on.doc") }
            .help("Copy the predicate")
        Button(action: openSchema) { Label("Telemetry Schema", systemImage: "curlybraces") }
            .help("Telemetry Schema: every key a record has")
        if isWindow {
            Button {
                search.isPoppedOut = false
                dismiss()
            } label: { Label("Dock", systemImage: "sidebar.right") }
                .help("Put the predicate editor back beside the tables")
        } else {
            Button {
                search.isPoppedOut = true
                openWindow(id: ProjectSutroApp.predicateEditorWindow)
            } label: { Label("Open in a Window", systemImage: "macwindow.on.rectangle") }
                .help("Open the predicate editor in its own window")
        }
    }

    // MARK: Editor
    /// - Parameter problem: Why the draft can't be applied.
    /// - Returns: The code editor over its status bar.
    private func editorBox(problem: String?) -> some View {
        let empty = search.draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        let clauses = Self.clauses(in: search.draft)
        let status = empty ? "Type a key path, an operator and a value."
            : problem ?? "Valid predicate · \(clauses) \(clauses == 1 ? "clause" : "clauses")"
        let color: Color = empty ? .secondary : problem == nil ? .green : .red
        return VStack(spacing: 0) {
            PredicateTextView(text: $search.draft, editor: editor)
                .frame(minHeight: 150, idealHeight: 180, maxHeight: 260)
            Divider()
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Image(systemName: empty ? "info.circle" : problem == nil ? "checkmark.circle.fill"
                      : "exclamationmark.triangle.fill")
                    .foregroundStyle(color)
                /// Room for a key path and the one meant, all of it in the tooltip.
                Text(status).foregroundStyle(problem == nil ? Color.secondary : color).lineLimit(6)
                    .textSelection(.enabled).help(status)
                Spacer(minLength: 8)
                CaretPosition(editor: editor)
            }
            .font(.caption)
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(Color.primary.opacity(0.03))
        }
        .background(Color(nsColor: .textBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8)
            .strokeBorder(problem == nil ? Color(nsColor: .separatorColor) : .red.opacity(0.7)))
    }

    // MARK: Formatting
    /// - Parameter source: A predicate.
    /// - Returns: It with each AND and OR outside a string starting a new, indented line.
    static func formatted(_ source: String) -> String {
        var out = "", inString: Character?, depth = 0
        let words = EventSearchController.oneLine(source)
        var index = words.startIndex
        while index < words.endIndex {
            let character = words[index]
            if let quote = inString {
                if character == quote { inString = nil }
            } else if character == "\"" || character == "'" {
                inString = character
            } else if character == "(" || character == ")" {
                depth = max(0, depth + (character == "(" ? 1 : -1))
            } else if character == " ", let keyword = ["AND ", "OR "].first(where: {
                words[words.index(after: index)...].uppercased().hasPrefix($0)
            }) {
                /// Deeper inside parentheses, such as a SUBQUERY's conditions, deeper in.
                out += "\n" + String(repeating: "  ", count: depth + 1)
                    + String(words[words.index(after: index)...].prefix(keyword.count - 1))
                index = words.index(index, offsetBy: keyword.count)
                continue
            }
            out.append(character)
            index = words.index(after: index)
        }
        return out
    }

    /// - Parameter source: A predicate.
    /// - Returns: How many comparisons its ANDs and ORs join.
    static func clauses(in source: String) -> Int {
        PredicateSyntax.tokens(in: source)
            .filter { $0.kind == .keyword && ["AND", "OR"].contains($0.text.uppercased()) }
            .count + 1
    }
}

/// The pane's tools as its window's toolbar, when it's in its own window: the window's title bar is its header.
private struct WindowToolbar<Tools: View>: ViewModifier {
    let isWindow: Bool
    @ViewBuilder let tools: Tools

    func body(content: Content) -> some View {
        if isWindow {
            content.toolbar { ToolbarItemGroup(placement: .primaryAction) { tools } }
        } else {
            content
        }
    }
}

/// The predicate editor in its own window, popped out of the main window. Closing the window closes the editor; its
/// Dock button puts the editor back beside the tables.
struct PredicateEditorWindow: View {
    @ObservedObject var search: EventSearchController
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        PredicateEditorPane(search: search, model: search.queries, isWindow: true) {
            openWindow(id: ProjectSutroApp.schemaWindow)
        }
        .frame(minWidth: 380, minHeight: 520)
        .onAppear { search.isPoppedOut = true }
        .onDisappear {
            /// Closed, not docked.
            guard search.isPoppedOut else { return }
            search.isPoppedOut = false
            search.showsEditor = false
        }
    }
}

/// The editor's cursor position, alone in following it so moving the cursor redraws only this.
private struct CaretPosition: View {
    @ObservedObject var editor: PredicateEditorController

    var body: some View {
        Text("Ln \(editor.line), Col \(editor.column)").monospacedDigit().foregroundStyle(.secondary)
    }
}

/// One search of what can go in a predicate: related events, saved and recent predicates, and the record's key paths
/// by group, each badged as the completion list badges it. Lazy, and drawn again only when its search or what it
/// lists changes, not as the predicate is typed.
private struct PredicateLibraryList: View, Equatable {
    let query: String
    let saved: [EventSearchController.SavedPredicate]
    let recents: [String]
    let editor: PredicateEditorController
    /// Puts a predicate in the editor.
    let load: (String) -> Void
    let delete: (EventSearchController.SavedPredicate) -> Void

    /// The sections shown open without a search.
    @State private var expanded: Set<String> = [RecordKeyLibrary.relatedTitle, Self.savedTitle, "Record", "Process"]
    /// The sections closed during a search, which opens every one that matches: open again when the search changes.
    @State private var closedInSearch: Set<String> = []

    private static let savedTitle = "Saved", recentTitle = "Recent"

    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.query == rhs.query && lhs.saved == rhs.saved && lhs.recents == rhs.recents
    }

    /// A row: what it is, its name, what it is under it, its type, and what clicking it does.
    struct Item: Identifiable {
        let id: String
        let badge: CompletionBadge.Kind
        let name: String
        var detail: String?
        var type = ""
        var help: String?
        let action: () -> Void
    }

    var body: some View {
        let query = query.trimmingCharacters(in: .whitespaces).lowercased()
        let sections = self.sections.compactMap { title, items -> (String, [Item])? in
            let items = query.isEmpty ? items : items.filter {
                $0.name.lowercased().contains(query) || $0.detail?.lowercased().contains(query) == true
            }
            return items.isEmpty ? nil : (title, items)
        }
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0, pinnedViews: .sectionHeaders) {
                ForEach(sections, id: \.0) { title, items in
                    let isOpen = query.isEmpty ? expanded.contains(title) : !closedInSearch.contains(title)
                    Section {
                        if isOpen {
                            ForEach(items.prefix(400)) { item in
                                Button(action: item.action) { LibraryRow(item: item) }
                                    .buttonStyle(.plain)
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 3)
                                    .contextMenu {
                                        if let predicate = saved.first(where: { "saved:\($0.id)" == item.id }) {
                                            Button("Delete", role: .destructive) { delete(predicate) }
                                        }
                                    }
                            }
                        }
                    } header: {
                        header(title, count: items.count, isOpen: isOpen, searching: !query.isEmpty)
                    }
                }
            }
        }
        .overlay {
            if sections.isEmpty { Text("Nothing matches “\(query)”.").foregroundStyle(.secondary) }
        }
        .onChange(of: query) { _ in closedInSearch = [] }
    }

    /// Related events, Saved, Recent, then the record's keys by group.
    private var sections: [(String, [Item])] {
        let key = { (key: RecordKeyLibrary.Key) in
            Item(id: key.path, badge: key.type == "related" ? .related : .key, name: key.path, detail: key.detail,
                 type: key.type == "related" ? "" : key.type, help: key.summary) {
                editor.insert(key.insertion ?? key.path)
            }
        }
        let saved = saved.map { saved in
            Item(id: "saved:\(saved.id)", badge: .saved, name: saved.name,
                 detail: EventSearchController.oneLine(saved.source), help: saved.source) { load(saved.source) }
        }
        let recents = recents.map { source in
            Item(id: "recent:\(source)", badge: .recent, name: EventSearchController.oneLine(source), help: source) {
                load(source)
            }
        }
        let groups = RecordKeyLibrary.groups.map { ($0.title, $0.keys.map(key)) }
        return [groups[0], (Self.savedTitle, saved), (Self.recentTitle, recents)] + groups.dropFirst()
    }

    /// - Parameters:
    ///   - title: The section's title.
    ///   - count: How many rows it has.
    ///   - isOpen: Is it open?
    ///   - searching: Is a search showing every section that matches open?
    /// - Returns: Its header, which opens and closes it, with a search or without.
    private func header(_ title: String, count: Int, isOpen: Bool, searching: Bool) -> some View {
        Button {
            if searching {
                closedInSearch.formSymmetricDifference([title])
            } else {
                expanded.formSymmetricDifference([title])
            }
        } label: {
            HStack(spacing: 5) {
                Image(systemName: "chevron.right").font(.caption2.weight(.semibold))
                    .rotationEffect(.degrees(isOpen ? 90 : 0))
                Text(title)
                Spacer()
                Text("\(count)").monospacedDigit()
            }
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 5)
            .background(.bar)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(title), \(count) \(isOpen ? "open" : "closed")")
    }
}

/// One row of the library: its badge, its name and what it is, and its type.
private struct LibraryRow: View {
    let item: PredicateLibraryList.Item

    var body: some View {
        HStack(spacing: 8) {
            CompletionBadge(item.badge)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.name)
                    .font(item.badge == .saved ? .callout : .system(size: 11.5, design: .monospaced))
                    .lineLimit(1).truncationMode(.middle)
                if let detail = item.detail {
                    Text(detail).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer(minLength: 6)
            Text(item.type).font(.caption2).foregroundStyle(.secondary)
        }
        .frame(minHeight: 20)
        .contentShape(Rectangle())
        .help(item.help ?? "")
    }
}

/// What's applied and how it's going, Revert or Remove, and Apply (⌘↩). It alone follows the tables' queries, which
/// change with every event saved.
private struct PredicateEditorFooter: View {
    @ObservedObject var search: EventSearchController
    @ObservedObject var model: EventQueryModel
    /// Why the draft can't be applied.
    let problem: String?

    var body: some View {
        let draft = EventSearchController.oneLine(search.draft)
        let applied = search.applied.map { EventSearchController.oneLine($0.source) } ?? ""
        let unchanged = draft == applied
        HStack(spacing: 8) {
            Group {
                if problem != nil {
                    Label("Fix the predicate to apply it.", systemImage: "circle.fill").foregroundStyle(.secondary)
                } else if unchanged && model.isSearching {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Checking each event's record…").foregroundStyle(.secondary)
                    }
                } else if unchanged && !applied.isEmpty {
                    VStack(alignment: .leading, spacing: 1) {
                        Label("Applied · \(model.filteredCount.formatted()) of \(model.totalCount.formatted()) "
                              + "events match", systemImage: "circle.fill")
                        if model.unchecked.count > 0 {
                            let reason = model.unchecked.reason ?? ""
                            Text("\(model.unchecked.count.formatted()) couldn't be checked: \(reason)")
                                .foregroundStyle(.orange).lineLimit(1).help(reason)
                        }
                    }
                } else {
                    Label(draft.isEmpty ? "No predicate applied." : "Not applied yet.", systemImage: "circle")
                        .foregroundStyle(.secondary)
                }
            }
            .font(.caption)
            .labelStyle(StatusDotLabelStyle(color: problem == nil && unchanged && !applied.isEmpty
                                            ? .green : .secondary))
            Spacer()
            if unchanged && !applied.isEmpty {
                Button("Remove") {
                    search.clear()
                    search.draft = ""
                }
                .help("Stop filtering by this predicate")
            } else {
                Button("Revert") { search.draft = search.applied?.source ?? "" }
                    .disabled(unchanged)
            }
            Button {
                search.apply(search.draft)
            } label: {
                HStack(spacing: 5) {
                    Text("Apply")
                    Text("⌘↩").opacity(0.75)
                }
            }
            .buttonStyle(.borderedProminent)
            .keyboardShortcut(.return, modifiers: .command)
            .disabled(problem != nil || draft.isEmpty || unchanged)
            .help("Filter the tables by this predicate (⌘↩)")
        }
        .controlSize(.small)
        .padding(.horizontal, 12)
        .frame(height: 44)
    }
}

/// A status line's label: a small colored dot before the text.
private struct StatusDotLabelStyle: LabelStyle {
    let color: Color

    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 7, height: 7)
            configuration.title
        }
    }
}



// MARK: - Syntax
/// How a predicate's text is colored, as Xcode colors code, in light and dark.
enum PredicateSyntax {
    typealias Token = PredicateText.Token

    static let font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
    static let boldFont = NSFont.monospacedSystemFont(ofSize: 12, weight: .semibold)
    static let keyColor = dynamic(light: 0x0F68A0, dark: 0x67B7A4)
    static let keywordColor = dynamic(light: 0x9B2393, dark: 0xFC5FA3)
    static let stringColor = dynamic(light: 0xC41A16, dark: 0xFC6A5D)
    static let numberColor = dynamic(light: 0x1C00CF, dark: 0xD0BF69)
    static let variableColor = dynamic(light: 0x6C36A9, dark: 0xA167E6)

    /// - Parameter text: A predicate.
    /// - Returns: Its tokens, in order.
    static func tokens(in text: String) -> [Token] {
        PredicateText.tokens(in: text)
    }

    /// Color a predicate's text, and underline each key path from its first key that isn't where it puts it, as the
    /// predicate is refused for it.
    ///
    /// - Parameter storage: The editor's text.
    static func highlight(_ storage: NSTextStorage) {
        let full = NSRange(location: 0, length: storage.length)
        storage.beginEditing()
        storage.setAttributes([.font: font, .foregroundColor: NSColor.labelColor], range: full)
        for token in tokens(in: storage.string) {
            switch token.kind {
            case .string: storage.addAttribute(.foregroundColor, value: stringColor, range: token.range)
            case .number: storage.addAttribute(.foregroundColor, value: numberColor, range: token.range)
            case .comparison: storage.addAttribute(.foregroundColor, value: keywordColor, range: token.range)
            case .keyword:
                storage.addAttributes([.foregroundColor: keywordColor, .font: boldFont], range: token.range)
            case .function:
                storage.addAttribute(.foregroundColor, value: keywordColor, range: token.range)
            case .keyPath, .variable:
                storage.addAttribute(.foregroundColor, value: keyColor, range: token.range)
                let keys = PredicateText.keys(of: token)
                var offset = token.range.location
                /// `$e`, a SUBQUERY's related event, then its keys.
                if token.kind == .variable {
                    /// `$e.` before the keys, or all of a `$e` alone.
                    let length = (token.text as NSString).length
                        - (keys.isEmpty ? -1 : (keys.joined(separator: ".") as NSString).length)
                    storage.addAttributes([.foregroundColor: variableColor, .font: boldFont],
                                          range: NSRange(location: offset, length: length - 1))
                    offset += length
                }
                /// Related events, which a SUBQUERY goes through, are where they should be on their own.
                let valid = token.kind == .keyPath && keys.count == 1 && PredicateRelation(rawValue: keys[0]) != nil
                    ? keys.count : RecordKeyPaths.shared.validCount(of: keys)
                for (index, key) in keys.enumerated() {
                    let range = NSRange(location: offset, length: (key as NSString).length)
                    if index >= valid {
                        storage.addAttributes([.foregroundColor: NSColor.labelColor,
                                               .underlineStyle: NSUnderlineStyle.thick.union(.patternDot).rawValue,
                                               .underlineColor: NSColor.systemRed], range: range)
                    }
                    offset += range.length + 1
                }
            }
        }
        storage.endEditing()
    }

    /// - Parameters:
    ///   - light: The color in light mode, as 0xRRGGBB.
    ///   - dark: In dark mode.
    /// - Returns: A color that follows the appearance.
    private static func dynamic(light: Int, dark: Int) -> NSColor {
        NSColor(name: nil) { appearance in
            let hex = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light
            return NSColor(srgbRed: CGFloat(hex >> 16 & 0xFF) / 255, green: CGFloat(hex >> 8 & 0xFF) / 255,
                           blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
        }
    }
}


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


// MARK: - Keys
/// The record's key paths, from the telemetry schema Mac Monitor ships, grouped for the predicate editor: the related
/// events a SUBQUERY goes through, the record's own keys, the process's, and each event type's.
enum RecordKeyLibrary {
    struct Key: Identifiable, Hashable {
        let path: String
        /// Its JSON type: string, integer, boolean, array or object, or "related" for related events.
        let type: String
        /// What it is, under its path.
        var detail: String?
        /// What the schema says of it, as its help.
        var summary: String?
        /// What clicking it inserts, when not its path.
        var insertion: String?
        var id: String { path }
    }

    /// The related events' group's title.
    static let relatedTitle = "Related events"

    /// Each relation, inserting a SUBQUERY of it to edit.
    static let related = Group(title: relatedTitle, keys: PredicateRelation.allCases.map { relation in
        let conditions: String
        switch relation {
        case .events:
            conditions = #"$e.es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" "#
                + "AND $e.event.exec.target.executable.path == target_path"
        case .processGroup: conditions = #"$e.es_event_type == "ES_EVENT_TYPE_NOTIFY_CREATE""#
        case .sessionGroup: conditions = #"$e.es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#
        case .correlated: conditions = #"$e.target_path CONTAINS "NSCreateObjectFileImageFromMemory""#
        case .processEvents: conditions = #"$e.es_event_type == "ES_EVENT_TYPE_NOTIFY_OPEN""#
        }
        return Key(path: relation.rawValue, type: "related", detail: relation.summary,
                   insertion: "SUBQUERY(\(relation.rawValue), $e, \(conditions)).@count > 0")
    })

    struct Group: Identifiable {
        let title: String
        let keys: [Key]
        var id: String { title }
    }

    /// Related events, Record, Process, then each event type by name. An array's objects' keys aren't listed: the
    /// array is.
    static let groups: [Group] = {
        let keys = RecordKeyPaths.shared.nodes.compactMap { path, node -> Key? in
            path.isEmpty || node.type == "object" || node.isInArray
                ? nil : Key(path: path, type: node.type, summary: node.summary)
        }
        .sorted { $0.path < $1.path }

        var grouped: [String: [Key]] = [:]
        for key in keys {
            let parts = key.path.split(separator: ".")
            let title = parts.first == "process" ? "Process" : parts.first == "event" && parts.count > 1
                ? String(parts[1]) : "Record"
            grouped[title, default: []].append(key)
        }
        let order = ["Record", "Process", "exec"]
        let schemaGroups = grouped.sorted { a, b in
            let (i, j) = (order.firstIndex(of: a.key) ?? order.count, order.firstIndex(of: b.key) ?? order.count)
            return i != j ? i < j : a.key < b.key
        }
        .map { Group(title: $0.key, keys: $0.value) }
        return [related] + schemaGroups
    }()
}
