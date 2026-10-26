//
//  FactsDashboard.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/23/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Breakdown
/// One slice of a ``BreakdownBar``: a kind of event, or a way processes are signed.
struct BreakdownSegment: Identifiable {
    let title: String
    let color: Color
    let count: Int
    var id: String { title }
}

/// A bar of slices, each as wide as its share, over a legend. Click a slice to keep only its events, and again for all.
struct BreakdownBar: View {
    let segments: [BreakdownSegment]
    /// The slice kept, by title.
    @Binding var selection: String?

    var body: some View {
        let total = max(segments.reduce(0) { $0 + $1.count }, 1)
        VStack(alignment: .leading, spacing: 6) {
            GeometryReader { geometry in
                let width = geometry.size.width - CGFloat(max(segments.count - 1, 0)) * 2
                HStack(spacing: 2) {
                    ForEach(segments) { segment in
                        Button { pick(segment) } label: {
                            Rectangle().fill(segment.color)
                                .frame(width: max(2, width * CGFloat(segment.count) / CGFloat(total)))
                        }
                        .buttonStyle(.plain)
                        .opacity(selection == nil || selection == segment.title ? 1 : 0.3)
                        .help("\(segment.title): \(segment.count)")
                    }
                }
            }
            .frame(height: 8)
            .clipShape(Capsule())
            FlowLayout(spacing: 14) {
                ForEach(segments) { segment in
                    Button { pick(segment) } label: {
                        HStack(spacing: 6) {
                            RoundedRectangle(cornerRadius: 2).fill(segment.color).frame(width: 8, height: 8)
                            Text(segment.title)
                            Text("\(segment.count)").foregroundStyle(.secondary)
                        }
                        .font(.callout)
                    }
                    .buttonStyle(.plain)
                    .opacity(selection == nil || selection == segment.title ? 1 : 0.5)
                }
            }
        }
    }

    /// Keep only a slice's events, or all of them again.
    ///
    /// - Parameter segment: The slice clicked.
    private func pick(_ segment: BreakdownSegment) {
        selection = selection == segment.title ? nil : segment.title
    }
}


// MARK: - Insights
/// A card for something worth a look: its symbol, title, and what it's about. Click it to keep only its events.
struct InsightCard: View {
    let symbol: String
    let tint: Color
    let title: String
    /// What it's about, such as the files' names.
    let detail: String
    /// Why it's worth a look, shown on hover.
    let explanation: String
    let isOn: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: symbol)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.white)
                    .frame(width: 22, height: 22)
                    .background(tint, in: RoundedRectangle(cornerRadius: 6))
                VStack(alignment: .leading, spacing: 1) {
                    Text(title).font(.callout.weight(.semibold))
                    Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer(minLength: 0)
            }
            .padding(9)
            .background(isOn ? tint.opacity(0.18) : Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(isOn ? tint : .clear, lineWidth: 1.5))
            .contentShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
        .help(explanation)
    }

    /// - Parameter names: Names, such as the files a finding is about, with repeats.
    /// - Returns: Each name once, in order, joined by commas.
    static func detail(_ names: [String]) -> String {
        NSOrderedSet(array: names.filter { !$0.isEmpty }).array.compactMap { $0 as? String }.joined(separator: ", ")
    }
}

/// Insight cards in as many columns as fit.
struct InsightGrid<Content: View>: View {
    @ViewBuilder let content: () -> Content

    var body: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 220), spacing: 8)], spacing: 8, content: content)
    }
}


// MARK: - Filters
/// What the events are limited to, such as a kind or a finding, with a button to stop.
struct FilterToken: View {
    let title: String
    let color: Color
    let remove: () -> Void

    var body: some View {
        HStack(spacing: 4) {
            Text(title).font(.callout).lineLimit(1)
            Button(action: remove) { Image(systemName: "xmark.circle.fill") }
                .buttonStyle(.borderless)
                .foregroundStyle(.secondary)
                .accessibilityLabel("Stop limiting to \(title)")
        }
        .padding(.leading, 8)
        .padding(.trailing, 4)
        .padding(.vertical, 3)
        .background(color.opacity(0.2), in: RoundedRectangle(cornerRadius: 6))
        .fixedSize()
    }
}

/// One of ``FilterChips``.
struct FilterChip: Identifiable {
    /// What it keeps, such as an event type's short name.
    let key: String
    let symbol: String?
    let count: Int
    var id: String { key }
}

/// A chip for each value, such as each event type, that keeps only the values turned on. None on keeps them all.
struct FilterChips: View {
    let chips: [FilterChip]
    @Binding var selection: Set<String>

    var body: some View {
        FlowLayout(spacing: 6) {
            ForEach(chips) { chip in
                let isOn = selection.contains(chip.key)
                Button {
                    if isOn { selection.remove(chip.key) } else { selection.insert(chip.key) }
                } label: {
                    HStack(spacing: 5) {
                        if let symbol = chip.symbol { Image(systemName: symbol) }
                        Text(chip.key).font(.callout.monospaced())
                        Text("\(chip.count)").font(.callout).opacity(0.7)
                    }
                }
                .buttonStyle(ChipStyle(isOn: isOn))
            }
        }
    }

    /// Chips for the values of some events, most events first.
    ///
    /// - Parameters:
    ///   - values: Each event's value and its symbol.
    ///   - limit: The most chips.
    /// - Returns: The chips.
    static func chips(_ values: [(key: String, symbol: String?)], limit: Int = .max) -> [FilterChip] {
        var counts: [String: (symbol: String?, count: Int)] = [:]
        values.forEach { counts[$0.key, default: ($0.symbol, 0)].count += 1 }
        return counts
            .sorted { $0.value.count > $1.value.count || ($0.value.count == $1.value.count && $0.key < $1.key) }
            .prefix(limit)
            .map { FilterChip(key: $0.key, symbol: $0.value.symbol, count: $0.value.count) }
    }
}

/// A chip: outlined when off, filled with the accent color when on.
private struct ChipStyle: ButtonStyle {
    let isOn: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.vertical, 3)
            .padding(.horizontal, 8)
            .foregroundStyle(isOn ? Color.white : Color.primary)
            .background(isOn ? Color.accentColor : Color.clear, in: Capsule())
            .overlay(Capsule().strokeBorder(isOn ? Color.accentColor : Color(nsColor: .separatorColor)))
            .opacity(configuration.isPressed ? 0.7 : 1)
            .contentShape(Capsule())
    }
}

/// The kept filters, the search field, and how many events show.
struct DashboardSearchRow<Tokens: View>: View {
    @Binding var query: String
    let prompt: String
    let shown: Int
    let total: Int
    /// What's counted, such as "events".
    var noun = "events"
    /// What the events are limited to.
    @ViewBuilder let tokens: () -> Tokens

    var body: some View {
        HStack(spacing: 8) {
            tokens()
            SettingsSearchField(text: $query, prompt: prompt)
            Text(shown == total ? "\(shown) \(noun)" : "\(shown) of \(total)")
                .font(.callout)
                .monospacedDigit()
                .foregroundStyle(.secondary)
                .fixedSize()
        }
    }
}


// MARK: - Inspector
/// The selected event's details beside the events: what it is, why it's worth a look, its facts, and what to do with
/// it.
struct EventInspector: View {
    @Environment(\.openWindow) private var openEventFacts

    let symbol: String
    let color: Color
    let title: String
    let subtitle: String
    /// Why it's worth a look.
    let note: (text: String, symbol: String, tint: Color)?
    /// Each fact's name and value. Empty ones are left out.
    let facts: [(String, String)]
    let message: ESMessage
    /// The event tables' menu for it.
    let menu: FactsRowMenu
    let close: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: symbol)
                    .foregroundStyle(.white)
                    .frame(width: 26, height: 26)
                    .background(color, in: RoundedRectangle(cornerRadius: 7))
                VStack(alignment: .leading, spacing: 1) {
                    Text(title).font(.headline.monospaced()).lineLimit(1)
                    Text(subtitle).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button(action: close) {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(.red).imageScale(.large)
                }
                .buttonStyle(.borderless)
                .help("Close")
            }
            .padding(10)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    if let note {
                        Label(note.text, systemImage: note.symbol)
                            .font(.callout)
                            .padding(8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(note.tint.opacity(0.15), in: RoundedRectangle(cornerRadius: 8))
                    }
                    ForEach(facts.filter { !$0.1.isEmpty }, id: \.0) { name, value in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(name).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                            Text(value).font(.callout.monospaced()).textSelection(.enabled)
                        }
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            Divider()
            VStack(spacing: 6) {
                Button { openEventFacts(value: message.id) } label: {
                    Text("Open in Event Facts").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                Menu { menu } label: { Text("Actions").frame(maxWidth: .infinity) }
                    .frame(maxWidth: .infinity)
            }
            .padding(10)
        }
        .frame(width: 280)
        .background(Color.primary.opacity(0.03))
    }
}

/// The event tables' menu for an event: the exec menu for an exec, and the other events' menu otherwise.
struct FactsRowMenu: View {
    @Binding var allFilters: Filters
    let message: ESMessage
    let manager: EndpointSecurityManager
    let prefs: UserPrefs

    var body: some View {
        if message.event.exec != nil {
            TableExecEventContextMenu(allFilters: $allFilters, message: message)
                .environmentObject(manager)
                .environmentObject(prefs)
        } else {
            TableNonExecContextMenus(allFilters: $allFilters, message: message)
                .environmentObject(manager)
                .environmentObject(prefs)
        }
    }
}


// MARK: - Layout
extension View {
    /// The rounded panel the events and the inspector sit in.
    ///
    /// - Returns: The view in the panel.
    func dashboardPanel() -> some View {
        background(Color(nsColor: .controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color(nsColor: .separatorColor)))
    }
}

/// Lays its views out in rows, starting a new row when the next view doesn't fit, as text wraps.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        arrange(subviews, in: proposal.width ?? .infinity).size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        for (subview, point) in zip(subviews, arrange(subviews, in: bounds.width).points) {
            subview.place(at: CGPoint(x: bounds.minX + point.x, y: bounds.minY + point.y), proposal: .unspecified)
        }
    }

    /// - Parameters:
    ///   - subviews: The views.
    ///   - width: The width to fill.
    /// - Returns: Each view's top-left corner, and the size of them all.
    private func arrange(_ subviews: Subviews, in width: CGFloat) -> (points: [CGPoint], size: CGSize) {
        var points: [CGPoint] = []
        var x: CGFloat = 0, y: CGFloat = 0, line: CGFloat = 0, widest: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x > 0, x + size.width > width {
                x = 0
                y += line + spacing
                line = 0
            }
            points.append(CGPoint(x: x, y: y))
            x += size.width + spacing
            line = max(line, size.height)
            widest = max(widest, x - spacing)
        }
        return (points, CGSize(width: widest, height: y + line))
    }
}
