//
//  EventSearch.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/23/26.
//

import SwiftUI
import AppKit
import SutroESFramework


// MARK: - Search
/// The event tables' predicate search: the predicate the tables are filtered by, and the predicate editor's draft,
/// saved predicates and recent ones. The search field's context narrows the predicate's matches.
@MainActor
final class EventSearchController: ObservableObject {
    /// A predicate kept under a name, in the predicate editor's Saved list.
    struct SavedPredicate: Codable, Hashable, Identifiable {
        var name: String
        var source: String
        var id: String { name }
    }

    /// The predicate the event tables are filtered by.
    @Published private(set) var applied: StreamFilter.Predicate?
    /// Is the predicate editor showing, beside the tables or in its own window?
    @Published var showsEditor = false
    /// Is the predicate editor in its own window (``PredicateEditorWindow``) rather than beside the tables?
    @Published var isPoppedOut = false
    /// The main window's queries, for the editor's footer wherever it is.
    weak var queries: EventQueryModel?
    /// The predicate editor's text.
    @Published var draft = ""
    /// Is the predicate editor's text only white space?
    var isDraftBlank: Bool { draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
    /// Applied predicates, newest first.
    @Published private(set) var recents: [String]
    @Published private(set) var saved: [SavedPredicate]

    /// The most recent predicates kept.
    private static let recentLimit = 10
    private enum Key {
        static let recents = "recentSearchPredicates", saved = "savedSearchPredicates"
    }

    /// What Saved holds until a predicate is saved.
    static let starterPredicates = [
        SavedPredicate(name: "curl and wget", source: "process.executable.path ENDSWITH \"/curl\" "
                       + "OR process.executable.path ENDSWITH \"/wget\""),
        SavedPredicate(name: "Fake password prompts",
                       source: "event.exec.script_content CONTAINS[c] \"hidden answer\""),
        SavedPredicate(name: "Freshly compiled",
                       source: "ANY event.exec.target.codesigning_flag_names == \"CS_LINKER_SIGNED\""),
        SavedPredicate(name: "New executables", source: "event.exec.executable_age_ms < 300000"),
        SavedPredicate(name: "Reflective loading", source: "es_event_type == \"ES_EVENT_TYPE_NOTIFY_EXEC\" AND "
                       + "SUBQUERY(correlated, $e, $e.target_path CONTAINS \"NSCreateObjectFileImageFromMemory\")"
                       + ".@count > 0"),
    ]

    init(defaults: UserDefaults = .standard) {
        /// Read the schema's keys now, off the main thread, so the editor opens without reading them.
        DispatchQueue.global(qos: .utility).async {
            _ = RecordKeyLibrary.groups
        }
        recents = defaults.stringArray(forKey: Key.recents) ?? []
        saved = defaults.data(forKey: Key.saved).flatMap { try? JSONDecoder().decode([SavedPredicate].self, from: $0) }
            ?? Self.starterPredicates
    }

    /// Show the predicate editor with the predicate applied, or the draft left in it.
    func showEditor() {
        if let applied { draft = applied.source }
        showsEditor = true
    }
    
    /// Show or hide the predicate editor (View ▸ Predicate Editor, ⌥⌘F), or bring its window forward.
    ///
    /// - Parameter openWindow: Opens the editor's own window, when it's in one.
    func toggleEditor(_ openWindow: OpenWindowAction) {
        if isPoppedOut { return openWindow(id: ProjectSutroApp.predicateEditorWindow) }
        if showsEditor { showsEditor = false } else { showEditor() }
    }

    /// Why a predicate can't be applied.
    ///
    /// - Parameter source: The predicate.
    /// - Returns: The reason, or `nil` if it can be.
    func problem(with source: String) -> String? {
        do {
            _ = try StreamFilter.Predicate(source.trimmingCharacters(in: .whitespacesAndNewlines), for: .search)
            return nil
        } catch {
            return (error as? CommandLineUsageError)?.message ?? error.localizedDescription
        }
    }

    /// Filter the tables by a predicate, or by none when it's empty. A predicate that can't be applied changes
    /// nothing: the editor says why.
    ///
    /// - Parameter source: The predicate.
    func apply(_ source: String) {
        let trimmed = source.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return applied = nil }
        guard let predicate = try? StreamFilter.Predicate(trimmed, for: .search) else { return }
        applied = predicate
        remember(trimmed)
    }

    /// Stop filtering by a predicate, and empty the predicate editor.
    func clear() {
        applied = nil
        draft = ""
    }

    /// Keep a predicate under a name in Saved, replacing one of the same name.
    ///
    /// - Parameters:
    ///   - name: Its name.
    ///   - source: The predicate.
    func save(_ name: String, source: String) {
        saved.removeAll { $0.name == name }
        saved.insert(SavedPredicate(name: name, source: source), at: 0)
        UserDefaults.standard.set(try? JSONEncoder().encode(saved), forKey: Key.saved)
    }

    /// - Parameter predicate: A saved predicate to forget.
    func delete(_ predicate: SavedPredicate) {
        saved.removeAll { $0 == predicate }
        UserDefaults.standard.set(try? JSONEncoder().encode(saved), forKey: Key.saved)
    }

    func clearRecents() {
        recents = []
        UserDefaults.standard.removeObject(forKey: Key.recents)
    }

    /// - Parameter source: A predicate just applied, to put first in Recent.
    private func remember(_ source: String) {
        recents.removeAll { $0 == source }
        recents.insert(source, at: 0)
        recents = Array(recents.prefix(Self.recentLimit))
        UserDefaults.standard.set(recents, forKey: Key.recents)
    }

    /// - Parameter source: A predicate, perhaps on several lines.
    /// - Returns: It on one line, its runs of white space as single spaces.
    static func oneLine(_ source: String) -> String {
        source.split(whereSeparator: \.isWhitespace).joined(separator: " ")
    }
}


// MARK: - Search field
/// Edit ▸ Find… (⌘F): text with a find bar, such as Event Facts' JSON tab, shows it when it has the focus or when
/// its window has no event search field, and otherwise the main window's search field takes the focus.
@MainActor
enum FindCommand {
    static func perform() {
        guard let window = NSApp.keyWindow else { return }
        let frame = window.contentView?.superview ?? window.contentView
        let focused = (window.firstResponder as? NSTextView).flatMap { $0.usesFindBar ? $0 : nil }
        let search = frame?.firstDescendant(of: FixedWidthSearchField.self)
        let findable = window.contentView?.firstDescendant(of: NSTextView.self) {
            $0.usesFindBar && !$0.isHiddenOrHasHiddenAncestor
        }
        guard let textView = focused ?? (search == nil ? findable : nil) else {
            if let search { window.makeFirstResponder(search) }
            return
        }
        window.makeFirstResponder(textView)
        let item = NSMenuItem()
        item.tag = NSTextFinder.Action.showFindInterface.rawValue
        textView.performFindPanelAction(item)
    }
}

extension NSView {
    /// - Parameters:
    ///   - type: The kind of view.
    ///   - test: What else it must be.
    /// - Returns: The first view of that kind under this one, depth first, that passes the test.
    func firstDescendant<View: NSView>(of type: View.Type, where test: (View) -> Bool = { _ in true }) -> View? {
        for subview in subviews {
            if let view = subview as? View, test(view) { return view }
            if let view = subview.firstDescendant(of: type, where: test) { return view }
        }
        return nil
    }
}

/// The event tables' search field, AppKit's own, which filters by each event's context as you type, and with a
/// predicate applied narrows its matches.
struct EventSearchField: NSViewRepresentable {
    @Binding var text: String
    /// Is a predicate applied?
    let narrowsPredicate: Bool

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSSearchField {
        let field = FixedWidthSearchField()
        field.delegate = context.coordinator
        field.sendsSearchStringImmediately = true
        field.maximumRecents = 0
        field.lineBreakMode = .byTruncatingTail
        context.coordinator.field = field
        return field
    }

    func updateNSView(_ field: NSSearchField, context: Context) {
        context.coordinator.parent = self
        if field.stringValue != text { field.stringValue = text }
        field.placeholderString = narrowsPredicate ? "Filter matches by context" : "Filter by context"
        field.toolTip = narrowsPredicate ? "Narrow the predicate's matches to events whose context contains this" : nil
    }

    @MainActor
    final class Coordinator: NSObject, NSSearchFieldDelegate {
        var parent: EventSearchField
        weak var field: NSSearchField?

        init(_ parent: EventSearchField) {
            self.parent = parent
        }

        func controlTextDidChange(_ notification: Notification) {
            guard let field else { return }
            parent.text = field.stringValue
        }
    }
}

/// A search field with no natural width: one that isn't editable asks for its whole text's, which pushes its
/// magnifying glass and clear button out of a toolbar item.
final class FixedWidthSearchField: NSSearchField {
    override var intrinsicContentSize: NSSize {
        NSSize(width: NSView.noIntrinsicMetric, height: super.intrinsicContentSize.height)
    }
}

