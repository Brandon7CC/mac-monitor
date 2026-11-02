//
//  FilterView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 12/16/22.
//

import SwiftUI
import SutroESFramework
import OSLog


public struct Filters: Equatable {
    public var initiatingPaths: [String] = []
    public var targetPaths: [String] = []
    public var events: [String] = []
    public var userIDs: [String] = []
    
    public var rootIncludedInitiatingProcessPath: String?
    public var rootIncludedTargetProcessPath: String?
    public var shouldIncludeProcessSubTrees: Bool = false
    
    /// The number of filters set: each path, event and user hidden, and one for the selected process trees.
    public var totalFilters: Int {
        initiatingPaths.count + targetPaths.count + events.count + userIDs.count
            + (rootIncludedInitiatingProcessPath == nil && rootIncludedTargetProcessPath == nil ? 0 : 1)
    }
}


// MARK: - Filters sheet
/// The toolbar's Filters sheet: what's hidden from the tables, which finding and predicate they show only, and what
/// isn't recorded at all. It reads the Security Extension's subscriptions; ``FilterSheet`` lays it out.
struct FilterView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    /// "Drop platform binaries" only applies while recording, not to an open trace.
    @EnvironmentObject var traceSession: TraceSession

    @Binding var allFilters: Filters
    @Binding var filteredTelemetryShown: Bool
    @Binding var eventMaskEnabled: Bool
    @Binding var filterPlatform: Bool
    /// The tables' finding filter and predicate.
    @ObservedObject var search: EventSearchController
    /// Opens the predicate editor.
    let openPredicateEditor: () -> Void

    var body: some View {
        FilterSheet(allFilters: $allFilters, eventMaskEnabled: $eventMaskEnabled, filterPlatform: $filterPlatform,
                    isLive: traceSession.isLive, search: search,
                    subscribedEvents: {
                        let subscribed = systemExtensionManager.monitoredEventStrings
                        return supportedEvents.map { eventTypeToString(from: $0) }.filter(subscribed.contains)
                    },
                    togglePlatformBinaries: { systemExtensionManager.togglePlatformBinaries() },
                    openPredicateEditor: openPredicateEditor,
                    done: { filteredTelemetryShown = false })
            .onAppear { systemExtensionManager.requestEventSubscriptions() }
    }
}


/// The Filters sheet's layout: a search over every filter, then a card each for artifact filtering (open to start),
/// findings, the predicate, and recording, collapsed to its summary until it's opened.
struct FilterSheet: View {
    @Binding var allFilters: Filters
    @Binding var eventMaskEnabled: Bool
    @Binding var filterPlatform: Bool
    /// Is it recording, rather than showing a trace? Dropping platform binaries applies only then.
    let isLive: Bool
    @ObservedObject var search: EventSearchController
    /// The event types subscribed to, which the event mask hides.
    let subscribedEvents: () -> [String]
    let togglePlatformBinaries: () -> Void
    let openPredicateEditor: () -> Void
    let done: () -> Void

    @ObservedObject private var findings = FindingStore.shared
    @State private var query = ""
    /// The cards open without a search.
    @State private var open: Set<FilterCard.Kind> = [.artifacts]
    /// The cards closed during a search, which opens every one that matches: open again when the search changes.
    @State private var closedInSearch: Set<FilterCard.Kind> = []

    var body: some View {
        let query = query.trimmingCharacters(in: .whitespaces).lowercased()
        let cards = cards.compactMap { $0.matching(query) }
        VStack(spacing: 0) {
            HStack(spacing: 16) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Filters").font(.title2.bold())
                    Text(status).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                SettingsSearchField(text: $query, prompt: "Search filters, paths, indicators")
                    .frame(width: 300)
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 16)
            Divider()
            ScrollView {
                VStack(spacing: 10) {
                    ForEach(cards) { card in
                        let isOpen = query.isEmpty ? open.contains(card.kind) : !closedInSearch.contains(card.kind)
                        FilterCardView(card: card, isOpen: isOpen) {
                            if query.isEmpty {
                                open.formSymmetricDifference([card.kind])
                            } else {
                                closedInSearch.formSymmetricDifference([card.kind])
                            }
                        }
                    }
                    if cards.isEmpty {
                        Text("No filters match “\(query)”.").foregroundStyle(.secondary).padding(.vertical, 40)
                    }
                }
                .padding(.horizontal, 24)
                .padding(.vertical, 16)
            }
            .onChange(of: query) { _ in closedInSearch = [] }
            Divider()
            HStack(spacing: 12) {
                Text("Artifact filters hide events from view: Endpoint Security still delivers them, and Mac Monitor "
                     + "still records them.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Done", action: done)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 12)
        }
        .frame(minWidth: 760, idealWidth: 860, minHeight: 560, idealHeight: 720)
    }

    // MARK: Cards
    /// Artifact filtering, findings, the predicate, then recording.
    private var cards: [FilterCard] {
        [artifactCard, findingsCard, predicateCard, recordingCard]
    }

    private var artifactCard: FilterCard {
        let mask = FilterCard.Row(id: "mask", name: "Event mask",
                                  detail: "Hide every subscribed event type, then remove the ones to see",
                                  control: .toggle(Binding { eventMaskEnabled } set: { on in
                                      allFilters.events = on ? subscribedEvents() : []
                                      eventMaskEnabled = on
                                  }))
        /// A filter's row, which Remove takes off.
        func filter(_ name: String, _ detail: String, glyph: String? = nil, remove: @escaping () -> Void)
            -> FilterCard.Row {
            FilterCard.Row(id: "\(detail):\(name)", name: name, detail: detail, glyph: glyph, isMonospaced: true,
                           control: .buttons([.init(title: "Remove", isDestructive: true, action: remove)]))
        }
        let tree = allFilters.shouldIncludeProcessSubTrees ? ", with its process tree" : ""
        var rows = [mask]
        if let path = allFilters.rootIncludedInitiatingProcessPath {
            rows.append(filter(path, "Only this initiating process\(tree)") { removeInclusion() })
        }
        if let path = allFilters.rootIncludedTargetProcessPath {
            rows.append(filter(path, "Only this target process\(tree)") { removeInclusion() })
        }
        rows += allFilters.initiatingPaths.map { path in
            filter(path, "Initiating process path") { allFilters.initiatingPaths.removeAll { $0 == path } }
        }
        rows += allFilters.targetPaths.map { path in
            filter(path, "Target path") { allFilters.targetPaths.removeAll { $0 == path } }
        }
        rows += allFilters.userIDs.sorted().map { user in
            filter(user, "User ID") { allFilters.userIDs.removeAll { $0 == user } }
        }
        rows += allFilters.events.sorted().map { event in
            filter(event, "Endpoint Security event", glyph: eventStringToImage(from: event)) {
                allFilters.events.removeAll { $0 == event }
            }
        }
        let count = allFilters.totalFilters
        return FilterCard(kind: .artifacts, title: "Artifact filtering",
                          about: "Hide events from view by path, user, or event type", symbol: "eye.slash.fill",
                          tint: .blue, summary: count > 0 ? "\(count) on" : "Off", isOn: count > 0, rows: rows,
                          empty: rows.count == 1 ? "Right-click an event in the tables to hide its path, user, or type."
                            : nil)
    }

    private var findingsCard: FilterCard {
        /// The findings on that mark the tables, parsed once until they change (``FindingStore/offered``).
        let on = findings.offered
        var rows: [FilterCard.Row] = []
        if on.count > 1 || (search.findingSelection == .any && !on.isEmpty) {
            rows.append(findingRow(.any, "Any indicator", detail: "The events of every indicator that's on",
                                   symbol: "sparkle.magnifyingglass", tint: .orange))
        }
        rows += on.map { findingRow(.finding($0.id), $0.name, detail: $0.explanation, symbol: $0.symbol,
                                    tint: $0.tint) }
        /// A finding filter that's dropped keeps its row, which says why, so it can be switched off.
        if let selection = search.findingSelection, search.findingPredicate == nil {
            let detail = "\(droppedReason(selection)), so its events aren't filtered. Switch it off"
            rows.insert(findingRow(selection, search.findingName ?? "Indicator", detail: detail,
                                   symbol: "sparkle.magnifyingglass", tint: .gray), at: 0)
        }
        /// A dropped finding filter isn't on.
        let shown = search.filteringFinding
        return FilterCard(kind: .findings, title: "Indicators",
                          about: "Show only an indicator's events. Settings ▸ Indicators sets what each finds",
                          symbol: "sparkle.magnifyingglass", tint: .orange,
                          summary: shown ?? (search.findingSelection == nil ? "Off" : "Dropped"),
                          isOn: shown != nil, rows: rows,
                          empty: rows.isEmpty
                            ? "Turn on Event tables and Filters for an indicator in Settings ▸ Indicators." : nil)
    }

    private var predicateCard: FilterCard {
        var actions = [FilterCard.Row.Action(title: "Open Predicate Editor", action: openPredicateEditor)]
        if search.applied != nil {
            actions.insert(.init(title: "Remove", isDestructive: true, action: search.clear), at: 0)
        }
        let row = FilterCard.Row(id: "predicate", name: search.applied == nil ? "None applied" : "Applied",
                                 detail: search.applied.map { EventSearchController.oneLine($0.source) }
                                    ?? "Write one in the predicate editor (⌥⌘F)",
                                 isMonospacedDetail: search.applied != nil, control: .buttons(actions))
        return FilterCard(kind: .predicate, title: "Predicate",
                          about: "Show only the events whose record matches, as macmonitor stream --predicate does",
                          symbol: "curlybraces", tint: .purple, summary: search.applied == nil ? "Off" : "Applied",
                          isOn: search.applied != nil, rows: [row], empty: nil)
    }

    private var recordingCard: FilterCard {
        let row = FilterCard.Row(id: "platform", name: "Drop platform binaries",
                                 detail: "Drops most events Apple-signed processes initiate, unless they exec or fork "
                                    + "a non-platform process",
                                 tile: ("apple.logo", .gray),
                                 control: .toggle(Binding { filterPlatform } set: { _ in
                                     filterPlatform.toggle()
                                     togglePlatformBinaries()
                                 }),
                                 isDisabled: !isLive, help: isLive ? nil : "Applies while recording")
        return FilterCard(kind: .recording, title: "Recording",
                          about: "Drop events before they're recorded, while recording", symbol: "record.circle",
                          tint: .gray, summary: filterPlatform ? "Dropping platform binaries" : "Off",
                          isOn: filterPlatform, rows: [row], empty: nil)
    }

    /// What the header says is on.
    private var status: String {
        let count = allFilters.totalFilters
        let parts = [count > 0 ? "\(count) artifact \(count == 1 ? "filter" : "filters") on" : nil,
                     search.filteringFinding.map { "showing only \($0)" },
                     search.applied == nil ? nil : "a predicate applied",
                     filterPlatform ? "dropping platform binaries" : nil].compactMap { $0 }
        return parts.isEmpty ? "Every event shows." : parts.joined(separator: " · ").capitalizedFirst
    }

    // MARK: Findings
    /// - Parameters:
    ///   - selection: The finding filter it sets.
    ///   - name: The finding's name.
    ///   - detail: Why it's worth a look.
    ///   - symbol: Its SF Symbol.
    ///   - tint: Its color.
    /// - Returns: Its row, whose switch is on while it's the finding filter, and sets the finding filter or removes
    ///   it. The predicate editor and its predicate stay.
    private func findingRow(_ selection: FindingSelection, _ name: String, detail: String, symbol: String,
                            tint: Color) -> FilterCard.Row {
        let id = switch selection {
        case .any: "any"
        case .finding(let id): id.uuidString
        }
        return FilterCard.Row(id: "finding:\(id)", name: name, detail: detail, tile: (symbol, tint),
                              control: .toggle(Binding { search.findingSelection == selection } set: { on in
                                  search.filter(by: on ? selection : nil)
                              }))
    }

    /// - Parameter selection: A finding filter that's dropped.
    /// - Returns: Why, from Settings ▸ Indicators.
    private func droppedReason(_ selection: FindingSelection) -> String {
        guard case .finding(let id) = selection else { return "No indicator is offered anymore" }
        guard let finding = findings.findings.first(where: { $0.id == id }) else { return "It was deleted" }
        if !finding.isEnabled { return "It's switched off in Settings ▸ Indicators" }
        if !finding.showsInTables { return "Event tables and Filters is off for it in Settings ▸ Indicators" }
        return "Its predicate can't be used"
    }

    /// Stop showing only one process's events.
    private func removeInclusion() {
        allFilters.rootIncludedInitiatingProcessPath = nil
        allFilters.rootIncludedTargetProcessPath = nil
        allFilters.shouldIncludeProcessSubTrees = false
    }
}
