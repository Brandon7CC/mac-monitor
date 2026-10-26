//
//  PathMutingSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 5/18/23.
//

import SwiftUI
import AppKit
import SutroESFramework


// MARK: - Settings ▸ Path Muting
/// Settings ▸ Path Muting: the saved mute set the Security Extension keeps, as a table grouped by mute type or by
/// event. Selecting a mute opens an inspector beside the table with every event it covers. + adds a mute, − unmutes
/// the selected one, and ⋯ imports, exports, resets, or unmutes everything. Right-clicking a mute offers the rest.
struct PathMutingSettingsView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @StateObject private var files = MuteFileActions()
    /// The Add sheet's path: "Mute Another Way…" starts it with the mute's.
    @State private var pathToMute = ""

    @State private var searchScope: SearchScope = .path
    @State private var searchText = ""
    @State private var searchKind: MuteKind = .literal
    @AppStorage("settingsMuteGrouping") private var grouping: Grouping = .kind
    /// The selected row: its group, a line break, then its mute's ID, since a mute shows once per event it covers.
    @State private var selection: String?
    @State private var adding: AddRequest?
    @State private var confirmation: Confirmation?

    /// What the search looks at.
    enum SearchScope: String, CaseIterable, Identifiable {
        case path = "Path", kind = "Mute type", events = "Events"
        var id: String { rawValue }
    }

    /// How the table groups mutes.
    enum Grouping: String, CaseIterable, Identifiable {
        case kind = "Mute type", event = "Event"
        var id: String { rawValue }
    }

    /// The Add sheet, and what it starts with.
    struct AddRequest: Identifiable {
        let id = UUID()
        let kind: MuteKind
    }

    /// A change that empties or replaces the saved set, waiting for the user to confirm it.
    enum Confirmation: String, Identifiable {
        case unmuteAll, reset
        var id: String { rawValue }
    }

    /// A titled group of the table's rows.
    struct Group: Identifiable {
        let id: String
        let kind: MuteKind?
        let event: EventCatalog.Event?
        let mutes: [ESMutedPath]
    }

    /// Can this Mac Monitor change the saved set? One refused the event stream, or a standard user's, may only read it.
    private var canEdit: Bool { systemExtensionManager.canChangeSavedMutes }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SettingsPaneHeader(pane: .pathMuting)
                .padding(12)
                .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 12))
            notices
            searchBar
            HStack(spacing: 0) {
                VStack(spacing: 0) {
                    table
                    bottomBar
                }
                if let chosen {
                    Divider()
                    MuteInspector(mute: chosen, canEdit: canEdit, close: { selection = nil }, unmute: unmute)
                        .frame(width: 280)
                }
            }
            .background(Color(nsColor: .controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(.separator))
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .sheet(item: $adding) { request in
            MuteAddSheet(pathToMute: $pathToMute, kind: request.kind)
        }
        .alert(item: $confirmation) { confirmation in
            switch confirmation {
            case .unmuteAll:
                return Alert(title: Text("Unmute all paths?"),
                             message: Text("This empties the saved mute set and will dramatically increase event "
                                           + "count."),
                             primaryButton: .destructive(Text("Unmute All")) {
                                 systemExtensionManager.requestMutes(MuteRequest(.replace))
                             },
                             secondaryButton: .cancel())
            case .reset:
                return Alert(title: Text("Reset the saved mute set?"),
                             message: Text("""
                                Replace the saved mute set (\(mutes.count) mutes) with Mac Monitor's default set \
                                (\(MuteList.shippedDefault.count)). This applies right away, to Mac Monitor and to \
                                every macmonitor stream that follows the saved set.
                                """),
                             primaryButton: .destructive(Text("Reset to Default")) {
                                 systemExtensionManager.requestMutes(MuteRequest(.reset))
                             },
                             secondaryButton: .cancel())
            }
        }
        .alert("Saved mute set", isPresented: showsProblems, actions: {
            Button("OK", role: .cancel, action: {})
        }, message: {
            Text(MuteFileActions.summary(of: systemExtensionManager.muteProblems))
        })
        .modifier(MuteFileAlerts(actions: files, manager: systemExtensionManager))
        .onAppear { systemExtensionManager.requestMutes(MuteRequest(.list)) }
        /// Pick up changes `sudo macmonitor` made while the window was in the background.
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didBecomeKeyNotification)) { _ in
            systemExtensionManager.requestMutes(MuteRequest(.list))
        }
    }

    // MARK: Pieces

    /// What the Security Extension said about the saved set, and why a standard user's controls are off.
    @ViewBuilder private var notices: some View {
        if let notice = systemExtensionManager.muteNotice {
            Label(notice, systemImage: "exclamationmark.triangle.fill").symbolRenderingMode(.multicolor)
        }
        if systemExtensionManager.savedMutesNeedAdministrator, let reason = MuteAccess.standardUser.refusal?.problem {
            Label(reason, systemImage: "lock.fill").foregroundStyle(.secondary)
        }
    }

    /// The search, what it looks at, and how the table groups mutes.
    private var searchBar: some View {
        HStack(spacing: 10) {
            Picker("Search by", selection: $searchScope) {
                ForEach(SearchScope.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented).labelsHidden().fixedSize()
            if searchScope == .kind {
                Picker("Mute type", selection: $searchKind) {
                    ForEach(MuteKind.allCases) { Text($0.title).tag($0) }
                }
                .labelsHidden().fixedSize()
                Spacer(minLength: 0)
            } else {
                SettingsSearchField(text: $searchText, prompt: searchScope == .events ? "Search by event, such as open"
                                                                                       : "Search paths")
            }
            Text("Group by").foregroundStyle(.secondary)
            Picker("Group by", selection: $grouping) {
                ForEach(Grouping.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented).labelsHidden().fixedSize()
        }
    }

    /// The saved set, grouped.
    private var table: some View {
        List(selection: $selection) {
            ForEach(groups) { group in
                Section {
                    ForEach(group.mutes) { mute in
                        MuteRow(mute: mute, showsEvents: chosen == nil, showsKind: grouping == .event)
                            .tag(group.id + "\n" + mute.id)
                            .contextMenu { menu(for: mute) }
                    }
                } header: {
                    GroupHeader(group: group)
                }
            }
        }
        .listStyle(.inset(alternatesRowBackgrounds: true))
        .overlay {
            if groups.isEmpty {
                Text(mutes.isEmpty ? "The saved mute set is empty. Expect a lot of events, and more noise than signal."
                                   : "No mutes match.")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding()
            }
        }
    }

    /// + to add, − to unmute the selected mute, and ⋯ for the rest, as macOS tables have them.
    private var bottomBar: some View {
        HStack(spacing: 0) {
            Button { adding = AddRequest(kind: .literal) } label: {
                Image(systemName: "plus").frame(width: 24, height: 20)
            }
                .help("Add a path mute")
                .disabled(!canEdit)
            Divider().frame(height: 14)
            Button { chosen.map { unmute($0, []) } } label: {
                Image(systemName: "minus").frame(width: 24, height: 20)
                    .foregroundStyle(chosen != nil && canEdit ? Color.red : Color.secondary)
            }
            .help("Unmute the selected path")
            .disabled(chosen == nil || !canEdit)
            Divider().frame(height: 14)
            Menu {
                Button { files.chooseImport() } label: {
                    Label("Import Mutes…", systemImage: "square.and.arrow.down")
                }
                    .disabled(!canEdit)
                Button { files.exportSavedSet(from: systemExtensionManager) } label: {
                    Label("Export Saved Mute Set…", systemImage: "square.and.arrow.up")
                }
                Button { files.exportAppleSet(from: systemExtensionManager) } label: {
                    Label("Export Apple Mute Set…", systemImage: "apple.logo")
                }
                Divider()
                Button { confirmation = .reset } label: {
                    Label("Reset to Default…", systemImage: "arrow.counterclockwise")
                }
                .disabled(!canEdit)
                Button(role: .destructive) { confirmation = .unmuteAll } label: {
                    Label("Unmute All…", systemImage: "speaker.wave.2")
                }
                .disabled(!canEdit || mutes.isEmpty)
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.visible)
            .fixedSize()
            .padding(.horizontal, 6)
            .help("Import, export, reset, or unmute everything")
            Spacer()
            Text("\(mutes.count) \(mutes.count == 1 ? "mute" : "mutes") · Right-click a mute for more")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.trailing, 8)
        }
        .buttonStyle(.borderless)
        .padding(.horizontal, 4)
        .padding(.vertical, 3)
        .background(.bar)
        .overlay(alignment: .top) { Divider() }
    }

    /// A mute's right-click menu.
    ///
    /// - Parameter mute: The mute.
    /// - Returns: The menu's items.
    @ViewBuilder private func menu(for mute: ESMutedPath) -> some View {
        Button("Copy Path") {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(mute.path, forType: .string)
        }
        Button("Show in Finder") {
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: mute.path)])
        }
        .disabled(!FileManager.default.fileExists(atPath: mute.path))
        Divider()
        Button("Mute Another Way…") {
            pathToMute = mute.path
            adding = AddRequest(kind: MuteKind(rawValue: mute.type) ?? .literal)
        }
        .disabled(!canEdit)
        if !mute.events.isEmpty {
            Menu("Unmute Event") {
                ForEach(mute.events, id: \.self) { name in
                    let event = EventCatalog.event(named: name)
                    Button { unmute(mute, [name]) } label: { Label(event.title, systemImage: event.symbol) }
                }
            }
            .disabled(!canEdit)
        }
        Divider()
        Button("Unmute Path", role: .destructive) { unmute(mute, []) }.disabled(!canEdit)
    }

    // MARK: Data

    /// The saved set, as the Security Extension last sent it.
    private var mutes: [ESMutedPath] { systemExtensionManager.savedMutes }

    /// The mutes the search keeps: by path, by type, or by event.
    private var kept: [ESMutedPath] {
        let query = searchText.trimmingCharacters(in: .whitespaces).lowercased()
        return mutes.filter { mute in
            switch searchScope {
            case .kind: return mute.type == searchKind.rawValue
            case .path: return query.isEmpty || mute.path.lowercased().contains(query)
            case .events: return query.isEmpty || mute.events.contains { $0.lowercased().contains(query) }
            }
        }
    }

    /// The table's groups: one per mute type, or one per event after the mutes for every event.
    private var groups: [Group] {
        let ordered = { (mutes: [ESMutedPath]) in
            mutes.sorted { ($0.path.count, $0.path) < ($1.path.count, $1.path) }
        }
        switch grouping {
        case .kind:
            return MuteKind.allCases.compactMap { kind in
                let mutes = ordered(kept.filter { $0.type == kind.rawValue })
                return mutes.isEmpty ? nil : Group(id: kind.rawValue, kind: kind, event: nil, mutes: mutes)
            }
        case .event:
            let every = ordered(kept.filter { $0.events.isEmpty })
            let events = Set(kept.flatMap(\.events)).sorted()
            return (every.isEmpty ? [] : [Group(id: "every", kind: nil, event: nil, mutes: every)])
                + events.map { name in
                    Group(id: name, kind: nil, event: EventCatalog.event(named: name),
                          mutes: ordered(kept.filter { $0.events.contains(name) }))
                }
        }
    }

    /// The selected mute, if it's still in the saved set.
    private var chosen: ESMutedPath? {
        guard let id = selection?.split(separator: "\n").last.map(String.init) else { return nil }
        return mutes.first { $0.id == id }
    }

    /// Shows what the Security Extension refused or left out of the last change.
    private var showsProblems: Binding<Bool> {
        Binding(get: { !systemExtensionManager.muteProblems.isEmpty },
                set: { if !$0 { systemExtensionManager.muteProblems = [] } })
    }

    /// Unmute a path, or some of its events.
    ///
    /// - Parameters:
    ///   - mute: The mute.
    ///   - events: `ES_EVENT_TYPE_*` names to unmute. None removes the path.
    private func unmute(_ mute: ESMutedPath, _ events: [String]) {
        if events.isEmpty || Set(events) == Set(mute.events) { selection = nil }
        systemExtensionManager.puntPathToUnmute(pathToUnmute: mute.path, type: mute.type, events: events)
    }
}
