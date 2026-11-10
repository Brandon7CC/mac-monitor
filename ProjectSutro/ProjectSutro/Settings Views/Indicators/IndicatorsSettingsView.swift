//
//  IndicatorsSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/25/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Settings > Indicators
/// Settings > Indicators: what Event Facts points out, each a predicate on an event's record, as a card in
/// Correlation (among the events of the process an exec created) and Groups (among a group's execs), and what marks
/// events in the tables. Mac Monitor's own are there to start, to change, turn off, or restore. They're grouped by
/// MITRE ATT&CK tactic, and laid out as Settings > Subscriptions lays out events (``SettingsCatalog``): the list beside
/// the sections picks every indicator, a tactic that has one, those with none, those off, or those whose symbol marks
/// the tables (``IndicatorScope``), and a search finds them in all. Each indicator's row has its severity and its
/// switch, and clicking it edits it. Export writes the indicators listed, or one, to a JSON file to share, and Import
/// adds a file's (``IndicatorsFile``). The bell button opens this user's notifications for High and Medium matches
/// (``IndicatorAlertsSection``), and a row's menu stops or starts them for its indicator. Add Indicator is the pane's
/// prominent button.
///
/// The indicators are the Mac's, which the Security Extension keeps and runs on every event, for every user: each
/// change is asked of it. Where each shows, in Correlation, Groups and the tables, is this user's. While this Mac
/// Monitor may not change them, because another owns the event stream, the Security Extension is older than 3.1, or a
/// newer Mac Monitor saved them, they show read-only, with why. A user's Mac Monitor 3.0 indicators are offered once
/// (``IndicatorImportBanner``).
struct IndicatorsSettingsView: View {
    @ObservedObject private var store = IndicatorStore.shared
    /// This user's indicator notifications, for each row's Don't Notify.
    @ObservedObject private var alerts = IndicatorAlertCenter.shared
    /// The main window's search, whose queries preview what an indicator finds.
    @EnvironmentObject private var search: EventSearchController
    /// Mac Monitor's connection to the Security Extension, which the notifications popover reads.
    @EnvironmentObject private var manager: EndpointSecurityManager
    /// The indicator being edited, and whether it's new, decided as the editor opens.
    @State private var editing: IndicatorEditing?
    @State private var confirmsRestore = false
    /// What's typed in the search field, matched against each indicator's name, description, predicate and tactic.
    @State private var query = ""
    /// The row picked in the list.
    @State private var scope: IndicatorScope = .all
    /// The indicators being exported.
    @State private var exporting: IndicatorsFile?
    @State private var importing = false
    /// What an import did, or why it couldn't.
    @State private var imported: (title: String, message: String)?
    /// The indicator to scroll the sections to, until they have.
    @State private var revealed: AnyHashable?
    /// Is the notifications popover showing?
    @State private var showsAlerts = false

    var body: some View {
        let cards = IndicatorCard.cards(of: store.indicators, in: scope, search: query)
        let canChange = store.canChangeIndicators
        SettingsPage(pane: .indicators) {
            HStack(spacing: 10) {
                Text(summary).foregroundStyle(.secondary)
                Spacer()
                Button("Restore Defaults…") { confirmsRestore = true }
                    .disabled(store.isDefault || !canChange)
                Button("Import…") { importing = true }
                    .disabled(!canChange)
                    .help("Add indicators from a JSON file to this Mac's")
                Button("Export…") { exporting = IndicatorsFile(cards.flatMap(\.indicators)) }
                    .disabled(cards.isEmpty)
                    .help("Save the indicators listed to a JSON file to share")
                Button { showsAlerts.toggle() } label: {
                    Image(systemName: alerts.high || alerts.medium ? "bell.badge" : "bell.slash")
                }
                .help("Notifications for High and Medium matches")
                .accessibilityLabel("Notifications")
                .popover(isPresented: $showsAlerts, arrowEdge: .bottom) {
                    IndicatorAlertsSection().environmentObject(manager)
                }
                Button("Add Indicator…") { editing = .new(Self.newIndicator(in: scope.shown(search: query))) }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canChange)
            }
            if let offer = store.importOffer {
                IndicatorImportBanner(offer: offer, canChange: canChange, take: store.takeImportOffer,
                                      decline: store.declineImportOffer)
            }
            if let notice = notice {
                Label(notice, systemImage: canChange ? "info.circle.fill" : "lock.fill")
                    .font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            SettingsCatalog(query: $query, prompt: "Search indicators",
                            empty: IndicatorCard.emptyText(cards, in: scope, search: query), reveal: $revealed) {
                let groups = IndicatorScope.groups(for: store.indicators, search: query)
                ForEach(Array(groups.enumerated()), id: \.offset) { index, group in
                    if index > 0 { SettingsClassDivider() }
                    ForEach(group, id: \.self, content: scopeRow)
                }
            } sections: {
                ForEach(cards) { card in
                    SettingsClassSection(header: header(card), items: card.indicators,
                                         footer: card.id == cards.last?.id ? Self.predicateNote : nil, row: row)
                }
            }
        }
        .sheet(item: $editing) { editing in
            IndicatorEditorSheet(indicator: editing.indicator, model: search.queries, canChange: canChange,
                                 save: { store.save($0, from: editing.original) },
                                 delete: !editing.isNew && canChange ? { store.delete($0) } : nil)
        }
        .fileExporter(isPresented: Binding { exporting != nil } set: { if !$0 { exporting = nil } },
                      document: exporting, contentType: .json, defaultFilename: exporting?.defaultName) { _ in }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
            Self.importFile(result, into: store) { imported = ($0, $1) }
        }
        .alert(imported?.title ?? "", isPresented: Binding { imported != nil } set: { if !$0 { imported = nil } }) {
            Button("OK") {}
        } message: {
            Text(imported?.message ?? "")
        }
        .alert("The Security Extension didn't change the indicators",
               isPresented: Binding { store.engine.failure != nil } set: { if !$0 { store.engine.failure = nil } }) {
            Button("OK") {}
        } message: {
            Text(store.engine.failure ?? "")
        }
        .confirmationDialog("Restore Mac Monitor's indicators?", isPresented: $confirmsRestore) {
            Button("Restore Defaults", role: .destructive) { store.restoreDefaults() }
        } message: {
            Text("Indicators anyone added or changed are removed for every user of this Mac, and where each shows is "
                 + "put back for you.")
        }
        /// A row that's gone, such as the tactic the last of its indicators moved from, shows them all.
        .onChange(of: Array(IndicatorScope.groups(for: store.indicators).joined())) { rows in
            if !rows.contains(scope) { scope = .all }
        }
        /// Changes `macmonitor` or another user made, and the indicator Event Facts asked to show.
        .onAppear {
            store.engine.refresh()
            takeRevealRequest()
        }
        .onChange(of: store.revealRequest) { _ in takeRevealRequest() }
    }

    /// Show the indicator Event Facts' Indicators popover asked for: its tactic, scrolled to its row.
    private func takeRevealRequest() {
        guard let id = store.revealRequest else { return }
        store.revealRequest = nil
        guard let indicator = store.indicators.first(where: { $0.id == id }) else { return }
        query = ""
        scope = indicator.tactic.map(IndicatorScope.tactic) ?? .noTactic
        revealed = AnyHashable(indicator.id)
    }

    /// Why the indicators can't be changed here, or what the Security Extension says about them, if anything.
    private var notice: String? {
        let engine = store.engine
        if let notice = engine.notice { return notice }
        guard !store.canChangeIndicators, engine.connection == .connected else { return nil }
        return "Another Mac Monitor owns the event stream, so it alone may change this Mac's indicators. Where each "
            + "shows is yours to change."
    }

    /// How many are on, and how many draw their symbol in the tables.
    private var summary: String {
        let on = store.indicators.filter(\.isEnabled)
        return "\(on.count) of \(store.indicators.count) on, \(on.filter(\.showsInTables).count) with "
            + "their symbol in the event tables"
    }

    /// What every indicator's predicate is, under the last section.
    private static let predicateNote = "An indicator's predicate compares one event's record, as macmonitor stream "
        + "--predicate does. The Security Extension runs every indicator that's on as it captures each event, for "
        + "every user of this Mac. Settings > Telemetry Schema describes every key."

    /// - Parameter row: A row of the list of classes.
    /// - Returns: It, with how many of its indicators are on, picked by clicking, which stops the search.
    private func scopeRow(_ row: IndicatorScope) -> some View {
        SettingsClassRow(title: row.title, symbol: row.symbol, tint: row.tint, isBold: row == .all,
                         count: row.count(of: store.indicators, search: query), unit: "on",
                         isSelected: scope.highlights(row, search: query)) {
            scope = row
            query = ""
        }
        .help(row.tactic.map { "\($0.name), ATT&CK tactic \($0.identifier)" } ?? row.title)
    }

    /// - Parameter card: A tactic's indicators, or those with none.
    /// - Returns: Its section's header, which counts and turns on or off every one of the tactic's, as Subscriptions'
    ///   does a class's events. Its Turn All is off-limits while the Mac's indicators can't be changed.
    private func header(_ card: IndicatorCard) -> SettingsClassHeader {
        SettingsClassHeader(title: card.title, identifier: card.tactic?.identifier,
                            symbol: card.tactic?.symbol ?? IndicatorScope.noTactic.symbol,
                            tint: card.tactic?.tint ?? IndicatorScope.noTactic.tint, detail: card.summary,
                            allOn: card.allOn, canTurnAll: store.canChangeIndicators) { on in
            store.setEnabled(card.whole, on)
        }
    }

    /// - Parameter indicator: An indicator.
    /// - Returns: Its row, with its menu.
    private func row(_ indicator: Indicator) -> some View {
        let canChange = store.canChangeIndicators
        let silenced = alerts.silenced.contains(indicator.id)
        let problem = store.sensorProblem(of: indicator)
        return IndicatorRow(indicator: indicator, sensorProblem: problem, canChange: canChange, silenced: silenced,
                            save: { store.save($0, from: indicator) }, edit: { editing = .existing(indicator) })
            /// What Show in Settings scrolls to.
            .id(AnyHashable(indicator.id))
            .contextMenu {
                Button("Edit…") { editing = .existing(indicator) }
                Button("Export…") { exporting = IndicatorsFile([indicator]) }
                Button("Duplicate") {
                    var copy = indicator
                    copy.id = UUID()
                    copy.name += " copy"
                    store.save(copy, from: nil)
                }
                .disabled(!canChange)
                /// This user's, so it's never off-limits.
                Button(silenced ? "Notify" : "Don't Notify") { alerts.setSilenced(indicator.id, !silenced) }
                Divider()
                Button("Delete", role: .destructive) { store.delete(indicator) }
                    .disabled(!canChange)
            }
    }

    /// What Add Indicator starts from: in the tactic the sections show, if they show one.
    ///
    /// - Parameter scope: What the sections show.
    /// - Returns: The new indicator.
    private static func newIndicator(in scope: IndicatorScope) -> Indicator {
        var indicator = Indicator(name: "", description: "", symbol: "exclamationmark.magnifyingglass", color: .orange,
                                  predicate: "event.exec != nil")
        indicator.tactic = scope.tactic
        return indicator
    }
}
