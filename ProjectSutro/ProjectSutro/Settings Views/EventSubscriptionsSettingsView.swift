//
//  EventSubscriptionsSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 5/18/23.
//

import SwiftUI
import SutroESFramework


// MARK: - Settings ▸ Subscriptions
/// Settings ▸ Subscriptions: every event Mac Monitor supports on this Mac, by class of telemetry. A list beside the
/// events picks All events, every class in its own section, or one class, as System Settings ▸ Notifications picks an
/// app. Each event has a switch that subscribes the Security Extension to it or unsubscribes it right away, and its
/// symbol takes its class's color while it's on.
struct SubscriptionsSettingsView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Binding var allFilters: Filters
    @Binding var eventMaskEnabled: Bool

    var body: some View {
        SubscriptionsPane(subscribed: systemExtensionManager.monitoredEventStrings, set: { names, on in
            on ? subscribe(names) : unsubscribe(names)
            systemExtensionManager.requestEventSubscriptions()
        }, reset: reset, unsubscribeAll: unsubscribeAll)
            .onAppear { systemExtensionManager.requestEventSubscriptions() }
    }

    /// Subscribe to events. While the event filter is on, they join it too, so their events show.
    ///
    /// - Parameter names: The events' names.
    private func subscribe(_ names: [String]) {
        for name in names {
            if eventMaskEnabled && !allFilters.events.contains(name) { allFilters.events.append(name) }
            systemExtensionManager.puntEventToSubscribe(eventString: name)
        }
    }

    /// Unsubscribe from events.
    ///
    /// - Parameter names: The events' names.
    private func unsubscribe(_ names: [String]) {
        names.forEach { systemExtensionManager.puntEventToUnsubscribe(eventString: $0) }
    }

    /// Mac Monitor's default subscriptions, and nothing else.
    private func reset() {
        let defaults = Set(systemExtensionManager.getCoreEvents())
        let subscribed = systemExtensionManager.monitoredEventStrings
        unsubscribe(subscribed.subtracting(defaults).sorted())
        subscribe(defaults.subtracting(subscribed).sorted())
        systemExtensionManager.requestEventSubscriptions()
    }

    /// No subscriptions at all.
    private func unsubscribeAll() {
        unsubscribe(systemExtensionManager.monitoredEventStrings.sorted())
        systemExtensionManager.requestEventSubscriptions()
    }
}


/// The Subscriptions pane's layout: the classes beside their events, the search, and the pane's buttons.
struct SubscriptionsPane: View {
    /// What the Security Extension last said it's subscribed to.
    let subscribed: Set<String>
    /// Subscribes to events, or unsubscribes from them.
    let set: ([String], Bool) -> Void
    let reset: () -> Void
    let unsubscribeAll: () -> Void

    @State private var query = ""
    /// The class shown, or `nil` for All events.
    @State private var picked: String?
    @State private var confirmsUnsubscribeAll = false

    var body: some View {
        let query = query.trimmingCharacters(in: .whitespaces).lowercased()
        let listed = EventCatalog.groups.compactMap { $0.matching(query) }
        let shown = query.isEmpty && picked != nil ? listed.filter { $0.title == picked } : listed
        let total = EventCatalog.events.filter { subscribed.contains($0.name) }.count
        SettingsPage(pane: .subscriptions) {
            HStack(spacing: 10) {
                Text("\(total) of \(EventCatalog.events.count) events subscribed").foregroundStyle(.secondary)
                Spacer()
                Button("Reset Subscriptions", action: reset)
                    .help("Subscribe to Mac Monitor's default events, and unsubscribe from the rest.")
                Button("Unsubscribe from All…", role: .destructive) { confirmsUnsubscribeAll = true }
                    .disabled(subscribed.isEmpty)
            }
            if subscribed.isEmpty {
                Label("Mac Monitor isn't subscribed to any events, so it records nothing. Reset Subscriptions "
                      + "subscribes to its usual set again.", systemImage: "exclamationmark.triangle.fill")
                    .symbolRenderingMode(.multicolor)
            }
            HStack(alignment: .top, spacing: 16) {
                VStack(spacing: 10) {
                    SettingsSearchField(text: $query, prompt: "Search events")
                    ScrollView {
                        VStack(spacing: 1) {
                            ClassRow(title: "All events", symbol: "list.bullet", tint: .gray, isBold: true,
                                     count: query.isEmpty ? "\(total)/\(EventCatalog.events.count)"
                                        : "\(listed.reduce(0) { $0 + $1.events.count })",
                                     isSelected: query.isEmpty && picked == nil) { pick(nil) }
                            Divider().padding(.horizontal, 8).padding(.vertical, 3)
                            ForEach(listed) { group in
                                let count = group.events.filter { subscribed.contains($0.name) }.count
                                ClassRow(title: group.title, symbol: group.symbol, tint: group.tint, isBold: false,
                                         count: query.isEmpty ? "\(count)/\(group.events.count)"
                                            : "\(group.events.count)",
                                         isSelected: query.isEmpty && picked == group.title) { pick(group.title) }
                            }
                        }
                        .padding(4)
                    }
                    .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
                    .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(.separator))
                }
                .frame(width: 290)
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 18) {
                        ForEach(shown) { group in
                            /// Every event of its class, not only those the search finds.
                            let whole = EventCatalog.groups.first { $0.title == group.title } ?? group
                            ClassSection(group: group, whole: whole, subscribed: subscribed, set: set)
                        }
                        if shown.isEmpty {
                            Text("No events match.").foregroundStyle(.secondary)
                                .frame(maxWidth: .infinity).padding(.vertical, 40)
                        }
                    }
                    .padding(.trailing, 4)
                }
            }
        }
        .confirmationDialog("Unsubscribe from all events?", isPresented: $confirmsUnsubscribeAll) {
            Button("Unsubscribe from All", role: .destructive, action: unsubscribeAll)
        } message: {
            Text("Event subscriptions drive what Mac Monitor records. With none, it records nothing until you "
                 + "subscribe again.")
        }
    }

    /// Show a class, or every one, and stop searching.
    ///
    /// - Parameter title: The class's title, or `nil` for All events.
    private func pick(_ title: String?) {
        picked = title
        query = ""
    }
}


// MARK: - Classes
/// A class in the list beside the events: its tile, its name, and how many of its events are subscribed.
private struct ClassRow: View {
    let title: String
    let symbol: String
    let tint: Color
    let isBold: Bool
    let count: String
    let isSelected: Bool
    let pick: () -> Void

    var body: some View {
        Button(action: pick) {
            HStack(spacing: 10) {
                SettingsRowIcon(symbol, tint)
                Text(title).fontWeight(isBold ? .semibold : .regular).lineLimit(1)
                Spacer(minLength: 4)
                Text(count).monospacedDigit().font(.callout)
                    .foregroundStyle(isSelected ? Color.white.opacity(0.85) : .secondary)
            }
            .foregroundStyle(isSelected ? Color.white : .primary)
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(isSelected ? Color.accentColor : .clear, in: RoundedRectangle(cornerRadius: 7))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }
}


/// A class's section: its tile, name and count, Turn All On or Off, then its events.
private struct ClassSection: View {
    /// The class, with only the events the search finds.
    let group: EventCatalog.Group
    /// The class, with every event, which Turn All On or Off changes.
    let whole: EventCatalog.Group
    let subscribed: Set<String>
    /// Subscribes to events, or unsubscribes from them.
    let set: ([String], Bool) -> Void

    var body: some View {
        let count = whole.events.filter { subscribed.contains($0.name) }.count
        let every = count == whole.events.count
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                Image(systemName: group.symbol)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 32, height: 32)
                    .background(group.tint.gradient, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 1) {
                    Text(group.title).font(.title3.bold())
                    Text("\(count) of \(whole.events.count) subscribed").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button(every ? "Turn All Off" : "Turn All On") {
                    set(whole.events.map(\.name).filter { subscribed.contains($0) == every }, !every)
                }
                .controlSize(.small)
            }
            VStack(spacing: 0) {
                ForEach(Array(group.events.enumerated()), id: \.element.id) { index, event in
                    if index > 0 { Divider().padding(.leading, 50) }
                    SubscriptionRow(event: event, tint: group.tint, isOn: Binding {
                        subscribed.contains(event.name)
                    } set: { on in
                        set([event.name], on)
                    })
                }
            }
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(.separator))
        }
    }
}


/// One event: its symbol, in its class's color while it's subscribed, its name for people and its full name, Apple's
/// documentation, and its switch.
private struct SubscriptionRow: View {
    let event: EventCatalog.Event
    let tint: Color
    @Binding var isOn: Bool

    var body: some View {
        HStack(spacing: 12) {
            SettingsRowIcon(event.symbol, isOn ? tint : Color(nsColor: .tertiaryLabelColor))
            VStack(alignment: .leading, spacing: 1) {
                Text(event.title).foregroundStyle(isOn ? .primary : .secondary)
                Text(event.name).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
            }
            Spacer(minLength: 8)
            Link(destination: event.documentation) { Image(systemName: "book") }
                .help("Apple's documentation for \(event.name)")
                .accessibilityLabel("Documentation for \(event.title)")
            Toggle("Subscribe to \(event.title)", isOn: $isOn).labelsHidden().toggleStyle(.switch)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
    }
}


// MARK: - Presentation
private extension EventCatalog.Group {
    /// - Parameter query: A search, lowercased, or "".
    /// - Returns: The class with only its events the search finds, by name for people or full name, or `nil`.
    func matching(_ query: String) -> EventCatalog.Group? {
        guard !query.isEmpty else { return self }
        let events = events.filter { $0.title.lowercased().contains(query) || $0.name.lowercased().contains(query) }
        return events.isEmpty ? nil : EventCatalog.Group(title: title, events: events)
    }

    /// The class's SF Symbol.
    var symbol: String {
        switch title {
        case "Process": return "cpu"
        case "File system": return "doc"
        case "File metadata": return "tag"
        case "Memory": return "memorychip"
        case "Login and sessions": return "person.crop.circle"
        case "Authorization and privacy": return "hand.raised"
        case "Background items and profiles": return "gearshape.2"
        case "Directory services": return "person.2"
        case "IPC and kernel": return "arrow.left.arrow.right"
        case "XProtect": return "xmark.shield"
        default: return "ellipsis.circle"
        }
    }

    /// The class's color, its tile's and its subscribed events'.
    var tint: Color {
        switch title {
        case "Process": return .blue
        case "File system": return .teal
        case "File metadata": return .indigo
        case "Memory": return .purple
        case "Login and sessions": return .green
        case "Authorization and privacy": return .orange
        case "Background items and profiles": return .pink
        case "Directory services": return .brown
        case "IPC and kernel": return .cyan
        case "XProtect": return .red
        default: return .gray
        }
    }
}
