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
    
    
    public func totalFilters() -> Int {
        var sum: Int = initiatingPaths.count + targetPaths.count + events.count + userIDs.count
        if rootIncludedInitiatingProcessPath != nil || rootIncludedTargetProcessPath != nil {
            sum += 1
        }
        
        return sum
    }
}


// MARK: - Filters sheet
/// The toolbar's Filters sheet: what's hidden from the tables, which finding or predicate they show only, and what
/// isn't recorded at all. It reads the Security Extension's subscriptions; ``FilterSheet`` lays it out.
struct FilterView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    /// "Drop platform binaries" only applies while recording, not to an open trace.
    @EnvironmentObject var traceSession: TraceSession

    @Binding var allFilters: Filters
    @Binding var filteredTelemetryShown: Bool
    @Binding var filterSelection: Set<String>
    @Binding var filteringLongRunningProcs: Bool
    @Binding var eventMaskEnabled: Bool
    @Binding var filterPlatform: Bool
    /// The tables' predicate, which a finding's events are shown by.
    @ObservedObject var search: EventSearchController
    /// Opens the predicate editor.
    let openPredicateEditor: () -> Void

    var body: some View {
        FilterSheet(allFilters: $allFilters, eventMaskEnabled: $eventMaskEnabled, filterPlatform: $filterPlatform,
                    isLive: traceSession.isLive, search: search,
                    subscribedEvents: {
                        let subscribed = systemExtensionManager.getSimpleEventSubscriptions()
                        return getSupportedEventTypesSelectable().map(\.eventString).filter(subscribed.contains)
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
                SettingsSearchField(text: $query, prompt: "Search filters, paths, findings")
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
        let count = allFilters.totalFilters()
        return FilterCard(kind: .artifacts, title: "Artifact filtering",
                          about: "Hide events from view by path, user, or event type", symbol: "eye.slash.fill",
                          tint: .blue, summary: count > 0 ? "\(count) on" : "Off", isOn: count > 0, rows: rows,
                          empty: rows.count == 1 ? "Right-click an event in the tables to hide its path, user, or type."
                            : nil)
    }

    private var findingsCard: FilterCard {
        let on = findings.usable
        var rows: [FilterCard.Row] = []
        if on.count > 1 {
            rows.append(findingRow("Any finding", detail: "The events of every finding that's on",
                                   symbol: "sparkle.magnifyingglass", tint: .orange, predicate: anyFinding(on)))
        }
        rows += on.map { findingRow($0.name, detail: $0.explanation, symbol: $0.symbol, tint: $0.tint,
                                    predicate: $0.predicate) }
        let shown = appliedFinding(on)
        return FilterCard(kind: .findings, title: "Findings",
                          about: "Show only a finding's events. Settings ▸ Findings sets what each finds",
                          symbol: "sparkle.magnifyingglass", tint: .orange, summary: shown ?? "Off",
                          isOn: shown != nil, rows: rows,
                          empty: rows.isEmpty ? "Turn findings on in Settings ▸ Findings." : nil)
    }

    private var predicateCard: FilterCard {
        let shown = appliedFinding(findings.usable)
        var actions = [FilterCard.Row.Action(title: "Open Predicate Editor", action: openPredicateEditor)]
        if search.applied != nil {
            actions.insert(.init(title: "Remove", isDestructive: true) {
                search.clear()
                search.draft = ""
            }, at: 0)
        }
        let row = FilterCard.Row(id: "predicate",
                                 name: search.applied == nil ? "None applied" : shown.map { "From \($0)" } ?? "Applied",
                                 detail: search.applied.map { EventSearchController.oneLine($0.source) }
                                    ?? "Write one in the predicate editor (⌥⌘F)",
                                 isMonospacedDetail: search.applied != nil, control: .buttons(actions))
        return FilterCard(kind: .predicate, title: "Predicate",
                          about: "Show only the events whose record matches, as macmonitor stream --predicate does",
                          symbol: "curlybraces", tint: .purple,
                          summary: search.applied == nil ? "Off" : shown.map { "From \($0)" } ?? "Applied",
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
        let count = allFilters.totalFilters()
        let shown = appliedFinding(findings.usable)
        let parts = [count > 0 ? "\(count) artifact \(count == 1 ? "filter" : "filters") on" : nil,
                     search.applied == nil ? nil : shown.map { "showing only \($0)" } ?? "a predicate applied",
                     filterPlatform ? "dropping platform binaries" : nil].compactMap { $0 }
        return parts.isEmpty ? "Every event shows." : parts.joined(separator: " · ").capitalizedFirst
    }

    // MARK: Findings
    /// - Parameters:
    ///   - name: The finding's name.
    ///   - detail: Why it's worth a look.
    ///   - symbol: Its SF Symbol.
    ///   - tint: Its color.
    ///   - predicate: Its predicate.
    /// - Returns: Its row, whose switch is on while its predicate is applied, and applies it or removes it.
    private func findingRow(_ name: String, detail: String, symbol: String, tint: Color,
                            predicate: String) -> FilterCard.Row {
        FilterCard.Row(id: "finding:\(name)", name: name, detail: detail, tile: (symbol, tint),
                       control: .toggle(Binding { isApplied(predicate) } set: { on in
                           search.draft = on ? predicate : ""
                           on ? search.apply(predicate) : search.clear()
                       }))
    }

    /// - Parameter findings: The findings that are on.
    /// - Returns: The predicate of any of them.
    private func anyFinding(_ findings: [Finding]) -> String {
        findings.map { "(\(EventSearchController.oneLine($0.predicate)))" }.joined(separator: " OR ")
    }

    /// - Parameter findings: The findings that are on.
    /// - Returns: The name of the finding whose predicate is applied, "Any finding", or `nil`.
    private func appliedFinding(_ findings: [Finding]) -> String? {
        if findings.count > 1, isApplied(anyFinding(findings)) { return "Any finding" }
        return findings.first { isApplied($0.predicate) }?.name
    }

    /// - Parameter predicate: A predicate.
    /// - Returns: Is it the one applied?
    private func isApplied(_ predicate: String) -> Bool {
        search.applied.map { EventSearchController.oneLine($0.source) == EventSearchController.oneLine(predicate) }
            ?? false
    }

    /// Stop showing only one process's events.
    private func removeInclusion() {
        allFilters.rootIncludedInitiatingProcessPath = nil
        allFilters.rootIncludedTargetProcessPath = nil
        allFilters.shouldIncludeProcessSubTrees = false
    }
}


// MARK: - Cards
/// One kind of filter: its tile, name and what it does, a summary of what's on, and its rows.
struct FilterCard: Identifiable {
    enum Kind: Hashable {
        case artifacts, findings, predicate, recording
    }

    /// One filter: its name and what it is, and its switch or buttons.
    struct Row: Identifiable {
        struct Action {
            let title: String
            /// Does it remove a filter? It's a red button, as the sheet's Remove buttons always were.
            var isDestructive = false
            let action: () -> Void
        }

        enum Control {
            case toggle(Binding<Bool>)
            case buttons([Action])
        }

        let id: String
        let name: String
        var detail: String?
        /// A finding's tile, or the recording card's.
        var tile: (symbol: String, tint: Color)?
        /// An event type's symbol.
        var glyph: String?
        var isMonospaced = false
        var isMonospacedDetail = false
        let control: Control
        var isDisabled = false
        var help: String?
    }

    let kind: Kind
    let title: String
    let about: String
    let symbol: String
    let tint: Color
    let summary: String
    let isOn: Bool
    let rows: [Row]
    /// What an empty card says.
    let empty: String?

    var id: Kind { kind }

    /// - Parameter query: A search, lowercased, or "".
    /// - Returns: The card with only its rows that match, all of them when its name does, or `nil` when none match.
    func matching(_ query: String) -> FilterCard? {
        guard !query.isEmpty, !title.lowercased().contains(query) else { return self }
        let rows = rows.filter { "\($0.name) \($0.detail ?? "")".lowercased().contains(query) }
        guard !rows.isEmpty else { return nil }
        return FilterCard(kind: kind, title: title, about: about, symbol: symbol, tint: tint, summary: summary,
                          isOn: isOn, rows: rows, empty: nil)
    }
}


/// A card: its header, which opens and closes it, then its rows.
private struct FilterCardView: View {
    let card: FilterCard
    let isOpen: Bool
    let toggle: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button(action: toggle) {
                HStack(spacing: 12) {
                    Image(systemName: "chevron.right").font(.caption.weight(.bold)).foregroundStyle(.secondary)
                        .rotationEffect(.degrees(isOpen ? 90 : 0))
                    SettingsRowIcon(card.symbol, card.tint)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(card.title).font(.headline)
                        Text(card.about).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                    Spacer(minLength: 8)
                    Text(card.summary).font(.caption.weight(.semibold)).lineLimit(1)
                        .padding(.horizontal, 8).padding(.vertical, 2)
                        .foregroundStyle(card.isOn ? Color.accentColor : .secondary)
                        .background((card.isOn ? Color.accentColor : .secondary).opacity(0.15), in: Capsule())
                }
                .padding(12)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("\(card.title), \(card.summary), \(isOpen ? "open" : "closed")")
            if isOpen {
                VStack(spacing: 0) {
                    ForEach(card.rows) { row in
                        Divider()
                        FilterRowView(row: row)
                    }
                    if let empty = card.empty {
                        Divider()
                        Text(empty).font(.caption).foregroundStyle(.secondary).padding(.vertical, 8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding(.leading, 70)
                .padding(.trailing, 12)
                .padding(.bottom, 6)
            }
        }
        .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 10))
    }
}


/// A filter's row: its tile or symbol, its name over what it is, and its switch or buttons.
private struct FilterRowView: View {
    let row: FilterCard.Row

    var body: some View {
        HStack(spacing: 10) {
            if let tile = row.tile {
                SettingsRowIcon(tile.symbol, tile.tint)
            } else if let glyph = row.glyph {
                Image(systemName: glyph).foregroundStyle(.secondary).frame(width: 22)
            }
            VStack(alignment: .leading, spacing: 1) {
                Text(row.name).font(row.isMonospaced ? .callout.monospaced() : .callout).fontWeight(.semibold)
                    .lineLimit(1).truncationMode(.middle)
                if let detail = row.detail {
                    Text(detail).font(row.isMonospacedDetail ? .caption.monospaced() : .caption)
                        .foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
                }
            }
            .help(row.detail.map { "\(row.name)\n\($0)" } ?? row.name)
            Spacer(minLength: 8)
            switch row.control {
            case .toggle(let isOn):
                Toggle(row.name, isOn: isOn).labelsHidden().toggleStyle(.switch).controlSize(.small)
            case .buttons(let actions):
                ForEach(actions, id: \.title) { action in
                    Button(action.title, role: action.isDestructive ? .destructive : nil, action: action.action)
                        .buttonStyle(FilterActionStyle(isDestructive: action.isDestructive))
                        .controlSize(.small)
                }
            }
        }
        .padding(.vertical, 7)
        .disabled(row.isDisabled)
        .help(row.help ?? "")
    }
}


/// A filter's button: a red one for Remove, and the system's own otherwise.
private struct FilterActionStyle: PrimitiveButtonStyle {
    let isDestructive: Bool

    func makeBody(configuration: Configuration) -> some View {
        if isDestructive {
            Button(configuration).buttonStyle(.borderedProminent).tint(.red)
        } else {
            Button(configuration)
        }
    }
}


private extension String {
    /// It with its first letter capitalized, as a sentence starts.
    var capitalizedFirst: String { prefix(1).uppercased() + dropFirst() }
}
