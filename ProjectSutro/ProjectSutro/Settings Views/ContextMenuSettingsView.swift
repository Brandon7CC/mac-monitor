//
//  ContextMenuSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/23/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Settings ▸ Context Menus
/// Settings ▸ Context Menus: what right-clicking an event offers. Process executions have their own menu, so the
/// picker at the top chooses which menu the switches edit, and the preview shows that menu as the switches leave it.
struct ContextMenuSettingsView: View {
    @EnvironmentObject var userPrefs: UserPrefs
    @AppStorage("settingsContextMenuKind") private var kind: ContextMenuKind = .exec
    @State private var showsFolderEvents = false

    var body: some View {
        SettingsForm(pane: .eventTables) {
            Section {
                VStack(spacing: 14) {
                    Picker("Menu", selection: $kind) {
                        ForEach(ContextMenuKind.allCases) { Text($0.title).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(maxWidth: 360)
                    ContextMenuPreview(kind: kind)
                    Text("What right-clicking \(kind.example) shows, as the switches below are now.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 6)
            }
            Section {
                ForEach(ContextMenuOption.allCases) { option in
                    Toggle(isOn: option.binding(userPrefs, for: kind)) {
                        SettingsLabel(title: option.title, detail: option.key)
                    }
                }
            } header: {
                Text(kind == .exec ? "Process execution menu" : "Other events menu")
            } footer: {
                if kind == .other {
                    Text("For some events, muting or filtering a target path uses its folder: ~/Downloads for "
                         + "~/Downloads/example.txt.").foregroundStyle(.secondary)
                }
            }
            Section {
                LabeledContent {
                    Button("Show…") { showsFolderEvents = true }
                } label: {
                    SettingsIconLabel("Events that use the folder", detail: "Their target path is their folder.",
                                      symbol: "folder.fill", tint: .blue)
                }
                LabeledContent {
                    Button("Reset") { userPrefs.resetContextPreferences() }
                } label: {
                    SettingsIconLabel("Reset context menus", detail: "Both menus go back to how Mac Monitor ships.",
                                      symbol: "arrow.counterclockwise", tint: .gray)
                }
            }
        }
        .sheet(isPresented: $showsFolderEvents) { FolderTargetEventsSheet() }
    }
}


// MARK: - The menus
/// Which context menu: process executions', or every other event's.
enum ContextMenuKind: String, CaseIterable, Identifiable {
    case exec, other

    var id: String { rawValue }

    /// The picker's title.
    var title: String { self == .exec ? "Process execution" : "Other events" }

    /// The event the caption names.
    var example: String { self == .exec ? "a process execution" : "any other event" }
}


/// A context menu item the user can turn off, in the order Settings lists them.
enum ContextMenuOption: String, CaseIterable, Identifiable {
    case filterUser, filterProcessPath, filterTargetPath, muteProcessPath, muteTargetPath, unsubscribe

    var id: String { rawValue }

    /// The switch's title.
    var title: String {
        switch self {
        case .filterUser: return "Filter by user"
        case .filterProcessPath: return "Filter by process path"
        case .filterTargetPath: return "Filter by target path"
        case .muteProcessPath: return "Mute the process path"
        case .muteTargetPath: return "Mute the target path"
        case .unsubscribe: return "Unsubscribe from the event type"
        }
    }

    /// The key the item works on.
    var key: String {
        switch self {
        case .filterUser: return "initiating_euid_human"
        case .filterProcessPath, .muteProcessPath: return "initiating_process_path"
        case .filterTargetPath, .muteTargetPath: return "target_path"
        case .unsubscribe: return "es_event_type"
        }
    }

    /// The preference behind the switch, for one menu.
    ///
    /// - Parameters:
    ///   - prefs: The user's preferences.
    ///   - kind: Which menu.
    /// - Returns: The preference.
    func binding(_ prefs: UserPrefs, for kind: ContextMenuKind) -> Binding<Bool> {
        let exec = kind == .exec
        switch self {
        case .filterUser: return exec ? prefs.$contextExecInitiatingEUIDFilter : prefs.$contextInitiatingEUIDFilter
        case .filterProcessPath:
            return exec ? prefs.$contextExecInitiatingPathFilter : prefs.$contextInitiatingPathFilter
        case .filterTargetPath: return exec ? prefs.$contextExecTargetPathFilter : prefs.$contextTargetPathFilter
        case .muteProcessPath: return exec ? prefs.$contextExecInitiatingPathMute : prefs.$contextInitiatingPathMute
        case .muteTargetPath: return exec ? prefs.$contextExecTargetPathMute : prefs.$contextTargetPathMute
        case .unsubscribe: return exec ? prefs.$contextExecEventUnsubscribe : prefs.$contextEventUnsubscribe
        }
    }
}


// MARK: - Preview
/// One menu as `EventRowMenu` builds it, for a sample event, drawn as a macOS menu.
private struct ContextMenuPreview: View {
    @EnvironmentObject var userPrefs: UserPrefs
    let kind: ContextMenuKind

    /// A menu line: an item, a section's header, or a separator.
    private enum Line: Hashable {
        case item(String), header(String), separator
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                switch line {
                case .item(let title):
                    Text(title).lineLimit(1).truncationMode(.middle).padding(.horizontal, 10).padding(.vertical, 3)
                case .header(let title):
                    Text(title).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                        .padding(.horizontal, 10).padding(.top, 2).padding(.bottom, 1)
                case .separator:
                    Divider().padding(.horizontal, 10).padding(.vertical, 4)
                }
            }
        }
        .font(.system(size: 13))
        .padding(.vertical, 5)
        .frame(width: 360, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(.separator))
        .shadow(color: .black.opacity(0.25), radius: 10, y: 4)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Preview of the \(kind.title.lowercased()) menu")
    }

    /// The menu's lines, in `EventRowMenu`'s order.
    private var lines: [Line] {
        let on = { (option: ContextMenuOption) in option.binding(userPrefs, for: kind).wrappedValue }
        let exec = kind == .exec
        let event = exec ? "ES_EVENT_TYPE_NOTIFY_EXEC" : "ES_EVENT_TYPE_NOTIFY_OPEN"
        let process = exec ? "/bin/zsh" : "/usr/bin/curl", target = exec ? "/usr/bin/curl" : "/private/tmp/report.txt"
        var lines: [Line] = [.item("Event metadata"), .separator]
        if exec, on(.filterTargetPath) { lines.append(.item("Filter target path: \"\(target)\"")) }
        if on(.filterUser) && exec { lines.append(.item("Filter euid: \"root\"")) }
        if on(.filterProcessPath) { lines.append(.item("Filter initiating path: \"\(process)\"")) }
        if on(.filterUser) && !exec { lines.append(.item("Filter euid: \"root\"")) }
        lines.append(.item("Filter event: \"\(event)\""))
        lines += [.separator, .header("Select"), .item("→ Only: \"curl\" events"),
                  .item("↕ Full tree: \"curl\" events")]
        var advanced: [Line] = []
        if !exec, on(.filterTargetPath) { advanced.append(.item("Filter target path: \"/private/tmp/\"")) }
        if exec {
            if on(.muteTargetPath) { advanced.append(.item("Mute target path: \"curl\"")) }
            if on(.muteProcessPath) { advanced.append(.item("Mute initiating path: \"zsh\"")) }
        } else {
            if on(.muteProcessPath) { advanced.append(.item("Mute initiating path: \"\(process)\"")) }
            if on(.muteTargetPath) { advanced.append(.item("Mute target path event: \"/private/tmp/\"")) }
        }
        if on(.unsubscribe) { advanced.append(.item("Unsubscribe: \"\(event)\"")) }
        return lines + [.separator, .header("Advanced")] + advanced
    }
}


// MARK: - Folder targets
/// The events whose target path the context menus mute or filter by its folder.
private struct FolderTargetEventsSheet: View {
    @Environment(\.dismiss) private var dismiss

    /// The events, by name.
    private let events = supportedEvents.map { eventTypeToString(from: $0) }
        .filter { IntelligentEventTargeting.targetShouldBeParentDir(esEventType: $0) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Events that use the folder").font(.title3.bold())
            Text("Muting or filtering one of these events' target path from a context menu uses its folder. A file "
                 + "created at ~/Downloads/example.txt mutes or filters ~/Downloads.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            List(events, id: \.self) { event in
                Label(event, systemImage: eventStringToImage(from: event)).font(.body.monospaced())
            }
            .frame(minHeight: 220)
            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 500, height: 420)
    }
}
