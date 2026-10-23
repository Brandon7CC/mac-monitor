//
//  MuteAddSheet.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import SwiftUI
import AppKit
import SutroESFramework


/// Adds a path to the saved mute set: what to match (the process or the target, exactly or as a folder) and the
/// events to mute it for, every one or only some, with a sentence that says what the mute will do.
struct MuteAddSheet: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.dismiss) private var dismiss
    @Binding var pathToMute: String

    @State private var target: Bool
    @State private var prefix: Bool
    @State private var onlySome = false
    @State private var picked: Set<String> = []
    @State private var query = ""

    /// - Parameters:
    ///   - pathToMute: The path, which the sheet may start with.
    ///   - kind: How to match it at first.
    init(pathToMute: Binding<String>, kind: MuteKind = .literal) {
        _pathToMute = pathToMute
        _target = State(initialValue: kind.isTarget)
        _prefix = State(initialValue: kind.isPrefix)
    }

    /// The `ES_EVENT_TYPE_*` names Endpoint Security mutes by target path.
    private static let targetable = Set(allowedTargetPathEvents.map { eventTypeToString(from: $0) })

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header.padding([.horizontal, .top], 20).padding(.bottom, 12)
            Form {
                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Path")
                        HStack {
                            TextField("Path", text: $pathToMute, prompt: Text(placeholder))
                                .textFieldStyle(.roundedBorder)
                                .font(.body.monospaced())
                                .labelsHidden()
                            Button("Choose…") { choose() }
                        }
                        if let note {
                            Text(note.text).font(.caption).foregroundStyle(note.warns ? .orange : .secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    LabeledContent("Match") {
                        VStack(alignment: .leading, spacing: 6) {
                            Picker("Match the", selection: $target) {
                                Text("Process").tag(false).help("The executable that caused the event")
                                Text("Target").tag(true).help("The file or path the event is about")
                            }
                            .pickerStyle(.segmented).labelsHidden().fixedSize()
                            Picker("Match how", selection: $prefix) {
                                Text("This path exactly").tag(false)
                                Text("Anything under this folder").tag(true)
                            }
                            .pickerStyle(.segmented).labelsHidden().fixedSize()
                            HStack(spacing: 6) {
                                MuteTypeBadgeView(kind: kind)
                                Text(kind.rawValue).font(.caption.monospaced()).foregroundStyle(.secondary)
                            }
                        }
                    }
                    LabeledContent("Mute for") {
                        Picker("Mute for", selection: $onlySome) {
                            Text("Every event").tag(false)
                            Text("Only these events").tag(true)
                        }
                        .pickerStyle(.segmented).labelsHidden().fixedSize()
                    }
                }
                if onlySome { eventList }
                Section {
                    Label(summary, systemImage: "info.circle").foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Add Mute") { add() }.keyboardShortcut(.defaultAction).disabled(!isValid)
            }
            .padding(.horizontal, 20).padding(.vertical, 12)
        }
        .frame(width: 580, height: onlySome ? 700 : 490)
        .onChange(of: target) { _ in picked.formIntersection(Set(choices.map(\.name))) }
    }

    /// The sheet's title and what a mute does.
    private var header: some View {
        HStack(spacing: 12) {
            SettingsIconTile(pane: .pathMuting, size: 34)
            VStack(alignment: .leading, spacing: 2) {
                Text("Add Path Mute").font(.title3.bold())
                Text("Endpoint Security stops sending the events it matches, right away, to Mac Monitor and "
                     + "macmonitor.")
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// The events to choose from, searchable, grouped as Subscriptions groups them.
    private var eventList: some View {
        Section {
            SettingsSearchField(text: $query, prompt: "Search events")
            ForEach(shownGroups) { group in
                Text(group.title).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                ForEach(group.events) { event in
                    Toggle(isOn: Binding { picked.contains(event.name) } set: {
                        if $0 { picked.insert(event.name) } else { picked.remove(event.name) }
                    }) {
                        HStack(spacing: 8) {
                            Image(systemName: event.symbol).foregroundStyle(.secondary).frame(width: 18)
                            Text(event.title)
                            Spacer()
                            Text(event.shortName).font(.caption.monospaced()).foregroundStyle(.secondary)
                        }
                    }
                    .toggleStyle(.checkbox)
                }
            }
            if shownGroups.isEmpty { Text("No events match.").foregroundStyle(.secondary) }
        } header: {
            Text("\(picked.count) selected")
        } footer: {
            Text("Only events Mac Monitor subscribes to" + (target
                ? ", and that Endpoint Security can mute by target path." : "."))
                .foregroundStyle(.secondary)
        }
    }

    /// How the mute matches its path.
    private var kind: MuteKind { MuteKind(target: target, prefix: prefix) }

    /// The events a mute like this can cover: subscribed ones, and for a target, ones ES mutes by target path.
    private var choices: [EventCatalog.Event] {
        let subscribed = systemExtensionManager.monitoredEventStrings
        return EventCatalog.events.filter {
            subscribed.contains($0.name) && (!target || Self.targetable.contains($0.name))
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
            return events.isEmpty ? nil : EventCatalog.Group(title: group.title, events: events)
        }
    }

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

    /// Can the mute be added?
    private var isValid: Bool { hasPath && (!onlySome || !picked.isEmpty) }

    /// What's wrong with the path, or what to know about it, and whether it's a warning.
    private var note: (text: String, warns: Bool)? {
        if pathToMute.isEmpty {
            return (target ? "The file or folder whose events to mute." : "The executable whose events to mute.", false)
        }
        if !pathToMute.hasPrefix("/") { return ("A full path, starting with /.", true) }
        if prefix && !pathToMute.hasSuffix("/") {
            return ("End a folder with /, so \(pathToMute) doesn't also match \(pathToMute)X.", true)
        }
        if systemExtensionManager.simpleGetMutedPaths().contains(where: {
            $0.path == pathToMute && $0.type == kind.rawValue
        }) {
            return ("Already muted this way. Adding merges these events into it.", false)
        }
        return nil
    }

    /// What the mute will do, in a sentence.
    private var summary: String {
        guard hasPath else { return "Type a path to see what this mute does." }
        let names = choices.filter { picked.contains($0.name) }.map(\.shortName)
        let events = !onlySome ? "any events" : names.isEmpty ? "the events you choose"
            : ListFormatter.localizedString(byJoining: names) + " events"
        let whose: String
        switch kind {
        case .literal: whose = "from"
        case .prefix: whose = "from anything under"
        case .targetLiteral: whose = "about"
        case .targetPrefix: whose = "about anything under"
        }
        return "Endpoint Security won't send \(events) \(whose) \(pathToMute)."
    }

    /// Ask for the file or folder to mute.
    private func choose() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = !prefix
        panel.canChooseDirectories = true
        panel.treatsFilePackagesAsDirectories = true
        panel.title = "Choose what to mute"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        pathToMute = url.path + (prefix && !url.path.hasSuffix("/") ? "/" : "")
    }

    /// Send the mute to the Security Extension, which replies with the new saved set.
    private func add() {
        let events = onlySome ? choices.map(\.name).filter { picked.contains($0) } : []
        systemExtensionManager.puntPathToMute(pathToMute: pathToMute, muteCase: kind.esType, pathEvents: events)
        pathToMute = ""
        dismiss()
    }
}
