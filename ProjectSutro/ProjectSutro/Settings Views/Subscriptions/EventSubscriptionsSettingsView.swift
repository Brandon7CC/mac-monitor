//
//  EventSubscriptionsSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 5/18/23.
//

import SwiftUI
import SutroESFramework


// MARK: - Settings > Subscriptions
/// Settings > Subscriptions: every event Mac Monitor supports on this Mac, by class of telemetry. A list beside the
/// events picks All events, every class in its own section, or one class, as System Settings > Notifications picks an
/// app. Each event has a switch that subscribes the Security Extension to it or unsubscribes it right away, and its
/// symbol takes its class's color while it's on. An event with a field filter, such as Close's "Only modified files",
/// has a checkbox under its name that turns the filter on or off.
struct SubscriptionsSettingsView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Binding var allFilters: Filters
    @Binding var eventMaskEnabled: Bool

    var body: some View {
        SubscriptionsPane(subscribed: systemExtensionManager.monitoredEventStrings,
                          isLoaded: systemExtensionManager.hasEventSubscriptions, set: { names, on in
            on ? subscribe(names) : unsubscribe(names)
            systemExtensionManager.requestEventSubscriptions()
        }, reset: reset, unsubscribeAll: unsubscribeAll)
            .onAppear { systemExtensionManager.requestEventSubscriptions() }
    }

    /// Subscribe to events, or turn field filters on. While the event filter is on, events join it too, so they show.
    ///
    /// - Parameter names: The events' names, or field filters' wire names.
    private func subscribe(_ names: [String]) {
        for name in names {
            if eventMaskEnabled && FieldFilter(rawValue: name) == nil && !allFilters.events.contains(name) {
                allFilters.events.append(name)
            }
            systemExtensionManager.setSubscription(name, enabled: true)
        }
    }

    /// Unsubscribe from events, or turn field filters off.
    ///
    /// - Parameter names: The events' names, or field filters' wire names.
    private func unsubscribe(_ names: [String]) {
        names.forEach { systemExtensionManager.setSubscription($0, enabled: false) }
    }

    /// Mac Monitor's default field filters, then its default subscriptions, and nothing else. A Security Extension
    /// that can't apply the filters (older than 3.1.0) gets the defaults that need none, so it never records every
    /// close.
    private func reset() {
        systemExtensionManager.resetFieldFilters { applies in
            let defaults = Set(systemExtensionManager.getCoreEvents(appliesFieldFilters: applies))
            let subscribed = events(in: systemExtensionManager.monitoredEventStrings)
            unsubscribe(subscribed.subtracting(defaults).sorted())
            subscribe(defaults.subtracting(subscribed).sorted())
            systemExtensionManager.requestEventSubscriptions()
        }
    }

    /// No subscriptions at all. Field filters are left as they are.
    private func unsubscribeAll() {
        unsubscribe(events(in: systemExtensionManager.monitoredEventStrings).sorted())
        systemExtensionManager.requestEventSubscriptions()
    }

    /// The event names in what the Security Extension reports, without its field filters' wire names.
    ///
    /// - Parameter names: ``EndpointSecurityManager/monitoredEventStrings``.
    /// - Returns: The events alone.
    private func events(in names: Set<String>) -> Set<String> {
        names.filter { FieldFilter(rawValue: $0) == nil }
    }
}


/// The Subscriptions pane's layout: the classes beside their events, the search, and the pane's buttons.
struct SubscriptionsPane: View {
    /// What the Security Extension last said it's subscribed to.
    let subscribed: Set<String>
    /// Has the Security Extension said yet? Until it has, the pane counts nothing, warns of nothing, and its
    /// switches are off-limits: none subscribed isn't known, only not known yet.
    let isLoaded: Bool
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
                Text(isLoaded ? "\(total) of \(EventCatalog.events.count) events subscribed" : "Loading subscriptions")
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Reset Subscriptions", action: reset)
                    .help("Subscribe to Mac Monitor's default events, with their default filters (close: only "
                          + "modified files), and unsubscribe from the rest.")
                Button("Unsubscribe from All…", role: .destructive) { confirmsUnsubscribeAll = true }
                    .disabled(total == 0)
            }
            if isLoaded, total == 0 {
                Label("Mac Monitor isn't subscribed to any events, so it records nothing. Reset Subscriptions "
                      + "subscribes to its usual set again.", systemImage: "exclamationmark.triangle.fill")
                    .symbolRenderingMode(.multicolor)
            }
            SettingsCatalog(query: $query, prompt: "Search events", empty: shown.isEmpty ? "No events match." : nil) {
                SettingsClassRow(title: "All events", symbol: "list.bullet", tint: .gray, isBold: true,
                                 count: query.isEmpty ? "\(total)/\(EventCatalog.events.count)"
                                    : "\(listed.reduce(0) { $0 + $1.events.count })", unit: "subscribed",
                                 isSelected: query.isEmpty && picked == nil) { pick(nil) }
                SettingsClassDivider()
                ForEach(listed) { group in
                    let count = group.events.filter { subscribed.contains($0.name) }.count
                    SettingsClassRow(title: group.title, symbol: group.symbol, tint: group.tint, isBold: false,
                                     count: query.isEmpty ? "\(count)/\(group.events.count)" : "\(group.events.count)",
                                     unit: "subscribed",
                                     isSelected: query.isEmpty && picked == group.title) { pick(group.title) }
                }
            } sections: {
                ForEach(shown) { group in
                    /// Every event of its class, not only those the search finds.
                    let whole = EventCatalog.groups.first { $0.title == group.title } ?? group
                    ClassSection(group: group, whole: whole, subscribed: subscribed, set: set)
                }
            }
            .disabled(!isLoaded)
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
        SettingsClassSection(header: SettingsClassHeader(
            title: group.title, symbol: group.symbol, tint: group.tint,
            detail: "\(count) of \(whole.events.count) subscribed", allOn: every
        ) { on in
            set(whole.events.map(\.name).filter { subscribed.contains($0) != on }, on)
        }, items: group.events) { event in
            SubscriptionRow(event: event, tint: group.tint, isOn: Binding {
                subscribed.contains(event.name)
            } set: { on in
                set([event.name], on)
            }, subscribed: subscribed, set: set)
        }
    }
}


/// One event: its symbol, in its class's color while it's subscribed, its name for people and its full name, a
/// checkbox for each field filter it offers, Apple's documentation, and its switch.
private struct SubscriptionRow: View {
    let event: EventCatalog.Event
    let tint: Color
    @Binding var isOn: Bool
    /// What the Security Extension last said it's subscribed to, with the wire names of its field filters.
    let subscribed: Set<String>
    /// Subscribes to events or turns field filters on, or the reverse.
    let set: ([String], Bool) -> Void

    var body: some View {
        SettingsItemRow(title: event.title, symbol: event.symbol, tint: tint,
                        switchLabel: "Subscribe to \(event.title)", isOn: $isOn, badges: {}) {
            Text(event.name).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
            /// Disabled while the event is off, keeping the state the Security Extension holds.
            ForEach(FieldFilter.offered(for: eventStringToType(from: event.name)), id: \.self) { filter in
                Toggle(filter.title, isOn: Binding {
                    subscribed.contains(filter.rawValue)
                } set: { on in
                    set([filter.rawValue], on)
                })
                .toggleStyle(.checkbox)
                .controlSize(.small)
                .disabled(!isOn)
                .help(filter.help)
                .padding(.top, 3)
            }
        } accessory: {
            Link(destination: event.documentation) { Image(systemName: "book") }
                .help("Apple's documentation for \(event.name)")
                .accessibilityLabel("Documentation for \(event.title)")
        }
    }
}


// MARK: - Presentation
private extension EventCatalog.Group {
    /// - Parameter query: A search, lowercased, or "".
    /// - Returns: The class with only its events the search finds, by name for people, full name, or the title of a
    ///   field filter it offers, or `nil`.
    func matching(_ query: String) -> EventCatalog.Group? {
        guard !query.isEmpty else { return self }
        let events = events.filter { event in
            event.title.lowercased().contains(query) || event.name.lowercased().contains(query)
                || FieldFilter.offered(for: eventStringToType(from: event.name))
                    .contains { $0.title.lowercased().contains(query) }
        }
        return events.isEmpty ? nil : with(events)
    }
}
