//
//  MuteAddSheet.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
import AppKit
import SutroESFramework


/// Adds a path to the saved mute set: the path and how to mute it by, then Mute Path for every event
/// (`es_mute_path`), or Mute Path Events for the Endpoint Security client's events picked below
/// (`es_mute_path_events`).
struct MuteAddSheet: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.dismiss) private var dismiss
    @Binding var pathToMute: String

    @State private var kind: MuteKind
    @State private var picked: Set<String> = []
    @State private var query = ""

    /// - Parameters:
    ///   - pathToMute: The path, which the sheet may start with.
    ///   - kind: How to mute it by at first.
    init(pathToMute: Binding<String>, kind: MuteKind = .literal) {
        _pathToMute = pathToMute
        _kind = State(initialValue: kind)
    }

    /// The `ES_EVENT_TYPE_*` names Endpoint Security mutes by target path.
    private static let targetable = Set(allowedTargetPathEvents.map { eventTypeToString(from: $0) })

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Form {
                Section {
                    Label("To mute the path for every event, click Mute Path. To mute it only for the events "
                          + "selected below, click Mute Path Events.", systemImage: "info.square")
                        .foregroundStyle(.secondary)
                    /// The whole row, as the path reads from its start.
                    HStack {
                        TextField(text: $pathToMute, prompt: Text(placeholder)) { Text("Path") }
                            .labelsHidden()
                            .textFieldStyle(.roundedBorder)
                            .font(.body.monospaced())
                        Button("Choose…") { choose() }
                    }
                    if let note {
                        Text(note.text).font(.caption).foregroundStyle(note.warns ? .orange : .secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Picker(selection: $kind) {
                        ForEach(MuteKind.offered) { Text($0.detail).tag($0) }
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Mute by")
                            Text(kind.rawValue).font(.caption.monospaced()).foregroundStyle(.secondary)
                        }
                    }
                } header: {
                    Text("Path mute properties")
                }
                Section {
                    HStack {
                        SettingsSearchField(text: $query, prompt: "Search events")
                        Text("\(picked.count) selected").foregroundStyle(.secondary).monospacedDigit()
                    }
                    /// Its own scroll view, a fixed height: rows in the form itself fall past the sheet's bottom.
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 6) {
                            ForEach(shownGroups) { group in
                                Text(group.title).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                                    .padding(.top, 4)
                                ForEach(group.events) { eventRow($0) }
                            }
                            if shownGroups.isEmpty { Text("No events match.").foregroundStyle(.secondary) }
                        }
                        .padding(.vertical, 4)
                        .padding(.trailing, 12)
                    }
                    .frame(height: 290)
                } header: {
                    Text("Endpoint Security client properties")
                } footer: {
                    Text("The path is muted only for the events selected here. AUTH events have no effect here. "
                         + "Only events Mac Monitor subscribes to are listed"
                         + (kind.isTarget ? ", and only those Endpoint Security mutes by target path." : ".")
                         + " Subscribe to an event first to mute it.")
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Mute Path") { add(events: []) }
                    .disabled(!hasPath)
                    .keyboardShortcut(picked.isEmpty ? .defaultAction : nil)
                    .help("es_mute_path: mute the path for every event")
                Button("Mute Path Events") { add(events: pickedEvents) }
                    .disabled(!hasPath || picked.isEmpty)
                    .keyboardShortcut(picked.isEmpty ? nil : .defaultAction)
                    .help("es_mute_path_events: mute the path for the events selected")
            }
            .padding(.horizontal, 20).padding(.vertical, 12)
        }
        /// No taller than the Settings window it's on, whose height the form then scrolls in.
        .frame(width: 600)
        .frame(minHeight: 520, idealHeight: 700, maxHeight: 720)
        .onChange(of: kind) { _ in picked.formIntersection(Set(choices.map(\.name))) }
        .onAppear { systemExtensionManager.requestEventSubscriptions() }
    }

    /// One event to pick, by its `ES_EVENT_TYPE_NOTIFY_` name, with Apple's documentation.
    ///
    /// - Parameter event: The event.
    /// - Returns: Its row.
    private func eventRow(_ event: EventCatalog.Event) -> some View {
        HStack(spacing: 8) {
            Toggle(isOn: Binding { picked.contains(event.name) } set: {
                if $0 { picked.insert(event.name) } else { picked.remove(event.name) }
            }) {
                HStack(spacing: 8) {
                    Image(systemName: event.symbol).foregroundStyle(.secondary).frame(width: 18)
                    Text(event.name).font(.callout.monospaced())
                }
            }
            .toggleStyle(.checkbox)
            .help(event.title)
            Spacer()
            Link(destination: event.documentation) { Image(systemName: "book") }
                .help("Apple's documentation for \(event.name)")
                .accessibilityLabel("Documentation for \(event.title)")
        }
    }

    /// The events a mute like this can cover: subscribed ones, and by a target path, ones ES mutes by it.
    private var choices: [EventCatalog.Event] {
        let subscribed = systemExtensionManager.monitoredEventStrings
        return EventCatalog.events.filter {
            subscribed.contains($0.name) && (!kind.isTarget || Self.targetable.contains($0.name))
        }
    }

    /// ``choices``, grouped, with only the ones the search finds.
    private var shownGroups: [EventCatalog.Group] {
        let names = Set(choices.map(\.name))
        let query = query.trimmingCharacters(in: .whitespaces).lowercased()
        return EventCatalog.groups.compactMap { group in
            let events = group.events.filter {
                names.contains($0.name) && (query.isEmpty || $0.title.lowercased().contains(query)
                                            || $0.name.lowercased().contains(query))
            }
            return events.isEmpty ? nil : group.with(events)
        }
    }

    /// The events picked, in the list's order.
    private var pickedEvents: [String] { choices.map(\.name).filter { picked.contains($0) } }

    /// A path to show in the empty field.
    private var placeholder: String {
        switch kind {
        case .literal: return "/usr/libexec/logd"
        case .prefix: return "/System/Library/PrivateFrameworks/"
        case .targetLiteral: return "/dev/null"
        case .targetPrefix: return "/Library/Caches/"
        }
    }

    /// Is the path a full one?
    private var hasPath: Bool { pathToMute.hasPrefix("/") && pathToMute.count > 1 }

    /// What's wrong with the path, or what to know about it, and whether it's a warning.
    private var note: (text: String, warns: Bool)? {
        if pathToMute.isEmpty {
            return (kind.isTarget ? "The event's target: the file or folder it's about."
                    : "The initiating process's executable.", false)
        }
        if !pathToMute.hasPrefix("/") { return ("A full path, starting with /.", true) }
        if kind.isPrefix && !pathToMute.hasSuffix("/") {
            return ("A prefix matches by text: end a folder with /, so \(pathToMute) doesn't also match "
                    + "\(pathToMute)X.", true)
        }
        if systemExtensionManager.savedMutes.contains(where: {
            $0.path == pathToMute && $0.type == kind.rawValue
        }) {
            return ("Already muted this way. Adding merges these events into it.", false)
        }
        return nil
    }

    /// Ask for the file or folder to mute.
    private func choose() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = !kind.isPrefix
        panel.canChooseDirectories = true
        panel.treatsFilePackagesAsDirectories = true
        panel.title = "Choose what to mute"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        pathToMute = url.path + (kind.isPrefix && !url.path.hasSuffix("/") ? "/" : "")
    }

    /// Send the mute to the Security Extension, which replies with the new saved set.
    ///
    /// - Parameter events: The events to mute the path for, or none for every event.
    private func add(events: [String]) {
        systemExtensionManager.puntPathToMute(pathToMute: pathToMute, muteCase: kind.esType, pathEvents: events)
        pathToMute = ""
        dismiss()
    }
}
