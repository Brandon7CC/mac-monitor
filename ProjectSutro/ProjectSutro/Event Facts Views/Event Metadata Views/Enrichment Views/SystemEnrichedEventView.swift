//
//  SystemEnrichedEventView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/18/22.
//

import SwiftUI
import CoreData
import SutroESFramework


// MARK: - Correlation tab
/// Event Facts' Correlation tab: the events the exec's process instigated, as a dashboard. A summary and a bar of
/// their kinds sit above cards for the findings worth a look, then a search, a chip for each event type, and the
/// events as a list or a timeline, with the selected one's details beside them. A kind, a finding or a chip keeps
/// only its events.
struct SystemEnrichedEventView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject var userPrefs: UserPrefs
    @Environment(\.openWindow) private var openEventFacts

    @Binding var allFilters: Filters
    /// The exec whose process's events are shown.
    var selectedMessage: ESMessage

    /// How the events are shown.
    enum Presentation: String, CaseIterable, Identifiable {
        case list = "List", timeline = "Timeline"
        var id: Self { self }
    }

    @State private var summary: CorrelationSummary?
    @State private var presentation = Presentation.list
    @State private var query = ""
    /// The kind kept, by title.
    @State private var kind: String?
    @State private var finding: Finding?
    /// The event types whose chips are on, by short name.
    @State private var types: Set<String> = []
    @State private var selection: NSManagedObjectID?

    var body: some View {
        Group {
            if let summary {
                dashboard(summary)
            } else {
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        /// One fetch per exec: `correlated_array` queries the store each time it's read.
        .task(id: selectedMessage.objectID) {
            summary = CorrelationSummary(exec: selectedMessage)
            (query, kind, finding, types, selection) = ("", nil, nil, [], nil)
        }
    }

    /// - Parameter summary: The process's events.
    /// - Returns: The dashboard.
    private func dashboard(_ summary: CorrelationSummary) -> some View {
        let rows = shown(summary)
        return VStack(alignment: .leading, spacing: 12) {
            header(summary)
            BreakdownBar(segments: summary.kinds.map { BreakdownSegment(title: $0.kind.title, color: $0.kind.color,
                                                                        count: $0.count) },
                         selection: $kind)
            if !summary.findings.isEmpty {
                InsightGrid {
                    ForEach(summary.findings, id: \.finding) { item in
                        let files = item.rows.map { ($0.target as NSString).lastPathComponent }
                        InsightCard(symbol: item.finding.symbol, tint: item.finding.tint,
                                    title: item.finding.title(item.rows.count), detail: InsightCard.detail(files),
                                    explanation: item.finding.explanation, isOn: finding == item.finding) {
                            finding = finding == item.finding ? nil : item.finding
                        }
                    }
                }
            }
            DashboardSearchRow(query: $query, prompt: "Search paths, signing IDs and details", shown: rows.count,
                               total: summary.rows.count) {
                if let kind {
                    let color = summary.kinds.first { $0.kind.title == kind }?.kind.color ?? .gray
                    FilterToken(title: kind, color: color) { self.kind = nil }
                }
                if let finding {
                    FilterToken(title: finding.title(summary.findings.first { $0.finding == finding }?.rows.count ?? 0),
                                color: finding.tint) { self.finding = nil }
                }
            }
            FilterChips(chips: FilterChips.chips(summary.rows.map { ($0.type, $0.symbol) }), selection: $types)
            HStack(spacing: 0) {
                switch presentation {
                case .list:
                    table(rows)
                case .timeline:
                    CorrelationTimeline(summary: summary, shown: Set(rows.map(\.id)), selection: $selection)
                }
                if let row = summary.rows.first(where: { $0.id == selection }) {
                    Divider()
                    inspector(row)
                }
            }
            .dashboardPanel()
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    /// The events that pass the kind, the finding, the chips and the search.
    ///
    /// - Parameter summary: The process's events.
    /// - Returns: The rows to show, oldest first.
    private func shown(_ summary: CorrelationSummary) -> [CorrelationSummary.Row] {
        let query = query.trimmingCharacters(in: .whitespaces).lowercased()
        return summary.rows.filter { row in
            (kind == nil || row.kind.title == kind) && (finding?.matches(row.message) ?? true)
                && (types.isEmpty || types.contains(row.type)) && (query.isEmpty || row.mentions(query))
        }
    }

    // MARK: Header
    /// The title, the summary line, and List or Timeline.
    ///
    /// - Parameter summary: The process's events.
    /// - Returns: The header.
    private func header(_ summary: CorrelationSummary) -> some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                (Text(summary.processName).font(.headline.monospaced()) + Text(" correlated events").font(.headline))
                Text("\(summary.rows.count) events in \(Self.seconds(summary.duration, sign: false)) · "
                     + "\(summary.kinds.count) \(summary.kinds.count == 1 ? "kind" : "kinds")")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Picker("Show as", selection: $presentation) {
                ForEach(Presentation.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
        }
    }

    // MARK: List
    /// The events as a table, oldest first. Double-click one for its Event Facts, or Control-click it for the event
    /// tables' menu.
    ///
    /// - Parameter rows: The events.
    /// - Returns: The table.
    private func table(_ rows: [CorrelationSummary.Row]) -> some View {
        Table(rows, selection: $selection) {
            TableColumn("Since exec") { row in
                Text(Self.seconds(row.seconds)).monospacedDigit().foregroundStyle(.secondary)
            }
            .width(min: 64, ideal: 72, max: 90)
            /// A finding's dot after the type: the card above says what it found.
            TableColumn("Event") { row in
                HStack(spacing: 6) {
                    Label(row.type, systemImage: row.symbol).font(.body.monospaced())
                    if let finding = row.finding {
                        Circle().fill(finding.tint).frame(width: 7, height: 7).help(finding.title(1))
                    }
                }
            }
            .width(min: 100, ideal: 130, max: 180)
            /// The rest of the width. Cut in the middle, which keeps both who it's about (an XPC connection's
            /// service) and where (a path's file name).
            /// No column for the detail, which the context mostly says: the inspector shows it.
            TableColumn("Context") { row in
                Text(row.context).font(.body.monospaced()).lineLimit(1).truncationMode(.middle).help(row.context)
            }
        }
        .contextMenu(forSelectionType: NSManagedObjectID.self) { ids in
            if let row = rows.first(where: { $0.id == ids.first }) { menu(row.message) }
        } primaryAction: { ids in
            if let row = rows.first(where: { $0.id == ids.first }) { openEventFacts(value: row.message.id) }
        }
        .overlay {
            if rows.isEmpty { Text("No correlated events match.").foregroundStyle(.secondary) }
        }
    }

    /// - Parameter message: An event.
    /// - Returns: The event tables' menu for it.
    private func menu(_ message: ESMessage) -> FactsRowMenu {
        FactsRowMenu(allFilters: $allFilters, message: message, manager: systemExtensionManager, prefs: userPrefs)
    }

    // MARK: Inspector
    /// - Parameter row: The selected event.
    /// - Returns: Its details: why it's worth a look, its facts, and what to do with it.
    private func inspector(_ row: CorrelationSummary.Row) -> some View {
        let process = row.message.process
        return EventInspector(
            symbol: row.symbol, color: row.kind.color, title: row.type,
            subtitle: "\(Self.seconds(row.seconds)) since exec",
            note: row.finding.map { ($0.explanation, $0.symbol, $0.tint) },
            facts: [("Context", row.context), ("Target", row.target), ("Detail", row.detail),
                    ("Event", row.message.es_event_type ?? ""),
                    ("Instigator", "\(process.executable?.name ?? "") (pid \(process.pid))"),
                    ("Signing ID", process.signing_id ?? "")],
            message: row.message, menu: menu(row.message)) { selection = nil }
    }

    // MARK: Formatting
    /// - Parameters:
    ///   - seconds: Seconds since the exec.
    ///   - sign: Start with "+".
    /// - Returns: Such as "+0.118 s", "+3.38 s" or "+2:05".
    static func seconds(_ seconds: Double, sign: Bool = true) -> String {
        let text = seconds < 1 ? String(format: "%.3f s", seconds)
            : seconds < 60 ? String(format: "%.2f s", seconds)
            : String(format: "%d:%02d", Int(seconds) / 60, Int(seconds) % 60)
        return sign ? "+" + text : text
    }
}


// MARK: - Timeline
/// The events as dots in a lane per kind, along a square-root scale of the time since the exec, so the burst right
/// after it spreads out. Events the filters leave out are faint. Click a dot to select its event.
private struct CorrelationTimeline: View {
    let summary: CorrelationSummary
    /// The events that pass the filters.
    let shown: Set<NSManagedObjectID>
    @Binding var selection: NSManagedObjectID?

    /// The labels' width.
    private let labelWidth: CGFloat = 150
    /// A dot's radius.
    private let radius: CGFloat = 6

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(summary.kinds, id: \.kind) { item in
                    HStack(spacing: 10) {
                        HStack(spacing: 6) {
                            RoundedRectangle(cornerRadius: 2).fill(item.kind.color).frame(width: 8, height: 8)
                            Text(item.kind.title).lineLimit(1)
                            Text("\(item.count)").foregroundStyle(.secondary)
                        }
                        .font(.callout)
                        .frame(width: labelWidth, alignment: .leading)
                        lane(summary.rows.filter { $0.kind == item.kind }, color: item.kind.color)
                    }
                }
                HStack(spacing: 10) {
                    Text("Since exec, √ scale").font(.caption).foregroundStyle(.secondary)
                        .frame(width: labelWidth, alignment: .leading)
                    ticks
                }
            }
            .padding(12)
        }
    }

    /// One kind's dots.
    ///
    /// - Parameters:
    ///   - rows: Its events.
    ///   - color: Its color.
    /// - Returns: The lane.
    private func lane(_ rows: [CorrelationSummary.Row], color: Color) -> some View {
        GeometryReader { geometry in
            Canvas { context, size in
                context.fill(Path(roundedRect: CGRect(origin: .zero, size: size), cornerRadius: 6),
                             with: .color(.primary.opacity(0.06)))
                for row in rows {
                    let dot = CGRect(x: x(row.seconds, in: size.width) - radius, y: size.height / 2 - radius,
                                     width: radius * 2, height: radius * 2)
                    context.fill(Path(ellipseIn: dot), with: .color(color.opacity(shown.contains(row.id) ? 1 : 0.18)))
                    if row.id == selection {
                        context.stroke(Path(ellipseIn: dot.insetBy(dx: -2.5, dy: -2.5)), with: .color(.primary),
                                       lineWidth: 2)
                    }
                }
            }
            .gesture(SpatialTapGesture().onEnded { tap in
                let nearest = rows.min { abs(x($0.seconds, in: geometry.size.width) - tap.location.x)
                    < abs(x($1.seconds, in: geometry.size.width) - tap.location.x) }
                if let nearest, abs(x(nearest.seconds, in: geometry.size.width) - tap.location.x) <= radius + 3 {
                    selection = nearest.id
                }
            })
            .help(rows.count == 1 ? "1 event" : "\(rows.count) events")
        }
        .frame(height: 24)
    }

    /// Labels along the scale, leaving out any that would crowd the one before.
    private var ticks: some View {
        GeometryReader { geometry in
            let candidates = [0, 0.05, 0.25, 1, 2, 5, 10, 30, 60, 300, 1800].filter { $0 < summary.duration * 0.85 }
                + [summary.duration]
            let placed = candidates.reduce(into: [(seconds: Double, x: CGFloat)]()) { placed, seconds in
                let position = x(seconds, in: geometry.size.width)
                if placed.last.map({ position - $0.x >= 44 }) ?? true { placed.append((seconds, position)) }
            }
            ForEach(placed, id: \.seconds) { tick in
                Text(tick.seconds == 0 ? "0" : SystemEnrichedEventView.seconds(tick.seconds, sign: false))
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .fixedSize()
                    .position(x: tick.x, y: 8)
            }
        }
        .frame(height: 16)
    }

    /// - Parameters:
    ///   - seconds: Seconds since the exec.
    ///   - width: The lane's width.
    /// - Returns: Where along the lane a dot goes.
    private func x(_ seconds: Double, in width: CGFloat) -> CGFloat {
        let share = summary.duration > 0 ? (seconds / summary.duration).squareRoot() : 0
        return radius + 1 + CGFloat(share) * (width - 2 * (radius + 1))
    }
}
