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
/// predicates to insert. Apply (⌘↩) filters the tables. The handle under the text drags its height.
struct PredicateEditorPane: View {
    /// The shortest the editor's text can be dragged.
    private static let minEditorHeight = 120.0
    /// The room the rest of the pane keeps below the editor's text.
    private static let reservedHeight = 240.0

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
    /// The editor's text height, kept between launches.
    @AppStorage("predicateEditorHeight") private var editorHeight = 180.0
    /// The pane's height, which bounds the editor's.
    @State private var paneHeight = 0.0

    /// The tallest the editor's text can be dragged: most of the pane.
    private var maxEditorHeight: Double {
        paneHeight > 0 ? max(Self.minEditorHeight, paneHeight - Self.reservedHeight) : .greatestFiniteMagnitude
    }

    var body: some View {
        let problem = search.isDraftBlank ? nil : search.problem(with: search.draft)
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
        .background(GeometryReader { proxy in
            Color.clear
                .onAppear { paneHeight = proxy.size.height }
                .onChange(of: proxy.size.height) { paneHeight = $0 }
        })
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
            .disabled(search.isDraftBlank)
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
        let empty = search.isDraftBlank
        let clauses = Self.clauses(in: search.draft)
        let status = empty ? "Type a key path, an operator and a value."
            : problem ?? "Valid predicate · \(clauses) \(clauses == 1 ? "clause" : "clauses")"
        let color: Color = empty ? .secondary : problem == nil ? .green : .red
        return VStack(spacing: 0) {
            PredicateTextView(text: $search.draft, editor: editor)
                .frame(height: min(max(editorHeight, Self.minEditorHeight), maxEditorHeight))
                .clipped()
            ResizeHandle(height: $editorHeight, range: Self.minEditorHeight...maxEditorHeight)
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
        PredicateText.tokens(in: source)
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

/// A divider the editor's height is dragged by, as a split view's is. The pointer shows it resizes up and down.
private struct ResizeHandle: View {
    @Binding var height: Double
    /// The heights it can be dragged between.
    let range: ClosedRange<Double>
    /// The height when the drag began.
    @State private var start: Double?
    /// Is the pointer over it, with its cursor pushed?
    @State private var hovering = false

    var body: some View {
        Divider()
            .padding(.vertical, 3)
            .contentShape(Rectangle())
            .onHover { inside in
                guard inside != hovering else { return }
                hovering = inside
                inside ? NSCursor.resizeUpDown.push() : NSCursor.pop()
            }
            .onDisappear { if hovering { NSCursor.pop() } }
            /// In the window's space: the handle moves with the drag, so its own space would shift under it.
            .gesture(DragGesture(minimumDistance: 1, coordinateSpace: .global)
                .onChanged { drag in
                    let start = start ?? min(max(height, range.lowerBound), range.upperBound)
                    self.start = start
                    height = min(max(start + drag.translation.height, range.lowerBound), range.upperBound)
                }
                .onEnded { _ in start = nil })
            .help("Drag to make the predicate editor taller or shorter")
    }
}

/// The editor's cursor position, alone in following it so moving the cursor redraws only this.
private struct CaretPosition: View {
    @ObservedObject var editor: PredicateEditorController

    var body: some View {
        Text("Ln \(editor.line), Col \(editor.column)").monospacedDigit().foregroundStyle(.secondary)
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
                Button("Remove", action: search.clear)
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
