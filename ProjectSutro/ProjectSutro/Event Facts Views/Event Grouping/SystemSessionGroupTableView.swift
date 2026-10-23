//
//  SystemSessionGroupTableView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/7/25.
//

import SwiftUI
import CoreData
import SutroESFramework


// MARK: - Groups tab
/// Event Facts' Groups tab: the execs in the event's process group or session, as a dashboard like Correlation's. A
/// summary and a bar of how they're signed sit above cards for the findings worth a look, then a search, a chip for
/// each executable, and the execs, with the selected one's details beside them. A way of signing, a finding or a chip
/// keeps only its execs.
struct SystemEventGroupTableViews: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    @Environment(\.openWindow) private var openEventFacts

    @Binding var allFilters: Filters
    var selectedMessage: ESMessage
    /// The process group's execs, newest first.
    var processGroup: [ESMessage]
    /// The session's execs, newest first.
    var sessionGroup: [ESMessage]

    @State private var chosenScope: GroupSummary.Scope?
    @State private var summary: GroupSummary?
    @State private var query = ""
    /// The way of signing kept, by title.
    @State private var signing: String?
    @State private var finding: GroupFinding?
    /// The executables whose chips are on, by name.
    @State private var names: Set<String> = []
    @State private var selection: NSManagedObjectID?

    /// The groups the event has.
    private var scopes: [GroupSummary.Scope] {
        GroupSummary.Scope.allCases.filter { !execs($0).isEmpty }
    }

    /// The group showing: the one chosen, or the first the event has.
    private var scope: GroupSummary.Scope {
        chosenScope.flatMap { scopes.contains($0) ? $0 : nil } ?? scopes.first ?? .process
    }

    var body: some View {
        Group {
            if let summary, summary.scope == scope {
                dashboard(summary)
            } else if scopes.isEmpty {
                Text("No group data available").foregroundStyle(.secondary)
            } else {
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        /// Made again when the event, the group, or its number of execs changes.
        .task(id: "\(selectedMessage.objectID)|\(scope)|\(execs(scope).count)") {
            summary = GroupSummary(scope: scope, execs: execs(scope), current: selectedMessage)
            (query, signing, finding, names, selection) = ("", nil, nil, [], nil)
        }
    }

    /// - Parameter scope: A group.
    /// - Returns: Its execs, newest first.
    private func execs(_ scope: GroupSummary.Scope) -> [ESMessage] {
        scope == .process ? processGroup : sessionGroup
    }

    /// - Parameter summary: The group's execs.
    /// - Returns: The dashboard.
    private func dashboard(_ summary: GroupSummary) -> some View {
        let rows = shown(summary)
        return VStack(alignment: .leading, spacing: 12) {
            header(summary)
            BreakdownBar(segments: summary.signings.map { BreakdownSegment(title: $0.signing.rawValue,
                                                                           color: $0.signing.color, count: $0.count) },
                         selection: $signing)
            if !summary.findings.isEmpty {
                InsightGrid {
                    ForEach(summary.findings, id: \.finding) { item in
                        InsightCard(symbol: item.finding.symbol, tint: item.finding.tint,
                                    title: item.finding.title(item.rows.count),
                                    detail: InsightCard.detail(item.rows.map(\.name)),
                                    explanation: item.finding.explanation, isOn: finding == item.finding) {
                            finding = finding == item.finding ? nil : item.finding
                        }
                    }
                }
            }
            DashboardSearchRow(query: $query, prompt: "Search names, paths, command lines and signing IDs",
                               shown: rows.count, total: summary.rows.count, noun: "processes") {
                if let signing {
                    FilterToken(title: signing, color: GroupSummary.Signing(rawValue: signing)?.color ?? .gray) {
                        self.signing = nil
                    }
                }
                if let finding {
                    FilterToken(title: finding.title(summary.findings.first { $0.finding == finding }?.rows.count ?? 0),
                                color: finding.tint) { self.finding = nil }
                }
            }
            FilterChips(chips: FilterChips.chips(summary.rows.map { ($0.name, nil) }, limit: 12), selection: $names)
            HStack(spacing: 0) {
                table(rows)
                if let row = summary.rows.first(where: { $0.id == selection }) {
                    Divider()
                    inspector(row, in: summary)
                }
            }
            .dashboardPanel()
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    /// The execs that pass the way of signing, the finding, the chips and the search.
    ///
    /// - Parameter summary: The group's execs.
    /// - Returns: The rows to show, oldest first.
    private func shown(_ summary: GroupSummary) -> [GroupSummary.Row] {
        let query = query.trimmingCharacters(in: .whitespaces).lowercased()
        return summary.rows.filter { row in
            (signing == nil || row.signing.rawValue == signing)
                && (finding.map { finding in row.message.event.exec.map(finding.matches) ?? false } ?? true)
                && (names.isEmpty || names.contains(row.name)) && (query.isEmpty || row.mentions(query))
        }
    }

    // MARK: Header
    /// The group's name and ID, the summary line, and the groups the event has.
    ///
    /// - Parameter summary: The group's execs.
    /// - Returns: The header.
    private func header(_ summary: GroupSummary) -> some View {
        let signers = Set(summary.rows.map(\.signer)).count
        return HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                (Text(summary.scope.rawValue + " ").font(.headline)
                 + Text(String(summary.identifier)).font(.headline.monospaced()))
                    .help(summary.scope.explanation)
                Text("\(summary.rows.count) \(summary.rows.count == 1 ? "process" : "processes") over "
                     + "\(GroupSummary.duration(summary.span)) · \(signers) \(signers == 1 ? "signer" : "signers")")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if scopes.count > 1 {
                Picker("Group", selection: Binding { scope } set: { chosenScope = $0 }) {
                    ForEach(scopes) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
            }
        }
    }

    // MARK: List
    /// The execs as a table, oldest first, with this event marked. Double-click one for its Event Facts, or
    /// Control-click it for the event tables' menu.
    ///
    /// - Parameter rows: The execs.
    /// - Returns: The table.
    private func table(_ rows: [GroupSummary.Row]) -> some View {
        Table(rows, selection: $selection) {
            TableColumn("Time") { row in
                HStack(spacing: 4) {
                    if row.isCurrent {
                        Image(systemName: "arrowtriangle.right.fill").foregroundStyle(.tint).help("This event")
                    }
                    Text(row.time).monospacedDigit().foregroundStyle(.secondary)
                }
            }
            .width(min: 90, ideal: 110, max: 130)
            TableColumn("Process") { row in
                HStack(spacing: 5) {
                    Image(systemName: row.signing.symbol).foregroundStyle(row.signing.color)
                        .help(row.signing.rawValue)
                    Text(row.name).font(.body.monospaced()).lineLimit(1)
                    if let finding = row.finding {
                        Circle().fill(finding.tint).frame(width: 7, height: 7).help(finding.title(1))
                    }
                }
            }
            .width(min: 100, ideal: 140, max: 200)
            /// The rest of the width, cut in the middle to keep the program and its last arguments.
            TableColumn("Command line") { row in
                Text(row.commandLine).font(.body.monospaced()).lineLimit(1).truncationMode(.middle)
                    .help(row.commandLine)
            }
            TableColumn("Signer") { row in
                Text(row.signer).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
            .width(min: 80, ideal: 130, max: 190)
            TableColumn("User") { row in
                Text(row.user).foregroundStyle(.secondary).lineLimit(1)
            }
            .width(min: 50, ideal: 70, max: 110)
        }
        .contextMenu(forSelectionType: NSManagedObjectID.self) { ids in
            if let row = rows.first(where: { $0.id == ids.first }) { menu(row.message) }
        } primaryAction: { ids in
            if let row = rows.first(where: { $0.id == ids.first }) { openEventFacts(value: row.message.id) }
        }
        .overlay {
            if rows.isEmpty { Text("No processes match.").foregroundStyle(.secondary) }
        }
    }

    /// - Parameter message: An event.
    /// - Returns: The event tables' menu for it.
    private func menu(_ message: ESMessage) -> FactsRowMenu {
        FactsRowMenu(allFilters: $allFilters, message: message, manager: systemExtensionManager, prefs: userPrefs)
    }

    // MARK: Inspector
    /// - Parameters:
    ///   - row: The selected exec.
    ///   - summary: Its group.
    /// - Returns: Its details: why it's worth a look, its facts, and what to do with it.
    private func inspector(_ row: GroupSummary.Row, in summary: GroupSummary) -> some View {
        let exec = row.message.event.exec
        let target = exec?.target
        return EventInspector(
            symbol: eventStringToImage(from: row.message.es_event_type ?? ""), color: row.signing.color,
            title: row.name, subtitle: row.isCurrent ? row.time + " · this event" : row.time,
            note: row.finding.map { ($0.explanation, $0.symbol, $0.tint) },
            facts: [("Command line", row.commandLine), ("Path", row.path),
                    ("Script", exec?.resolved_script_path ?? ""),
                    ("Executable age", exec?.executableAgeText.map { "Created \($0) before it ran" } ?? ""),
                    ("Signing", row.signing.rawValue),
                    ("Signing flags", target?.codesigningFlagNames.joined(separator: ", ") ?? ""),
                    ("Signing ID", target?.signing_id ?? ""), ("Team ID", target?.team_id ?? ""),
                    ("User", row.user), ("PID", target.map { "\($0.pid) (parent \($0.ppid))" } ?? ""),
                    ("Process group", target.map { "\($0.group_id)" } ?? ""),
                    ("Session", target.map { "\($0.session_id)" } ?? "")],
            message: row.message, menu: menu(row.message)) { selection = nil }
    }
}
