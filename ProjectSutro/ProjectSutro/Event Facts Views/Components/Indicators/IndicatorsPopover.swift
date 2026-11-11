//
//  IndicatorsPopover.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/8/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Popover
/// The indicators an event matched, a card each, in the order they're given: High first, then by name. Each card is
/// an indicator's symbol, name, tactic and severity, its description, its predicate behind a disclosure, with Copy
/// (``IndicatorPredicateSection``), and Show in Settings. Many scroll, and the popover is never taller than
/// ``maxHeight``.
///
/// When the events around the event matched indicators too (``RelatedIndicators``), the event's own are under
/// Target Indicators, and the others under Correlated Indicators and Group Indicators, each closed to start and
/// saying how many it holds.
struct IndicatorsPopover: View {
    let indicators: [Indicator]
    /// The indicators the events around the event matched.
    var related = RelatedIndicators()
    /// Closes the popover.
    let close: () -> Void
    @ObservedObject private var store = IndicatorStore.shared
    /// The cards' height, which the popover is until it's taller than ``maxHeight``.
    @State private var height: CGFloat = 0

    /// The popover's width, in points.
    static let width: CGFloat = 400
    /// The tallest the popover gets before its cards scroll, in points.
    static let maxHeight: CGFloat = 560

    var body: some View {
        /// The indicators Settings > Indicators lists. One the list no longer has comes from the event's verdict
        /// alone, with no predicate to show, and nothing in Settings to show.
        let listed = Set(store.indicators.map(\.id))
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if !related.isEmpty {
                    IndicatorSectionTitle(title: "Target Indicators", count: nil)
                        .help("The indicators this event matched.")
                    if indicators.isEmpty {
                        Text("This event matched none.").font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                }
                ForEach(indicators) { indicator in
                    IndicatorPopoverCard(indicator: indicator, isCard: indicators.count > 1 || !related.isEmpty,
                                         isListed: listed.contains(indicator.id), close: close)
                }
                RelatedIndicatorsSection(title: "Correlated Indicators", entries: related.correlated, listed: listed,
                                         help: "The indicators the events this process made matched. The "
                                            + "Correlation tab lists the events.", close: close)
                RelatedIndicatorsSection(title: "Group Indicators", entries: related.group, listed: listed,
                                         help: "The indicators other processes in this one's process group and "
                                            + "session matched. The Groups tab lists them.", close: close)
            }
            .padding(16)
            .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { height = $0 }
        }
        .frame(width: Self.width, height: min(max(height, 1), Self.maxHeight))
    }
}


// MARK: - Sections
/// A section's title in the Indicators popover: small, with how many indicators it holds when it's told.
private struct IndicatorSectionTitle: View {
    let title: String
    /// How many indicators the section holds, or `nil` to leave the number out.
    let count: Int?

    var body: some View {
        Text(count.map { "\(title) (\($0))" } ?? title)
            .font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
    }
}


/// The indicators some of the events around the event matched, behind their title: closed to start, a card each
/// when open, with how many events matched each. Nothing for a section with none.
private struct RelatedIndicatorsSection: View {
    let title: String
    let entries: [RelatedIndicators.Entry]
    /// The indicators Settings > Indicators lists, by identity.
    let listed: Set<UUID>
    /// What the section holds, as its title's help.
    let help: String
    /// Closes the popover.
    let close: () -> Void
    @State private var isOpen = false

    var body: some View {
        if !entries.isEmpty {
            Button {
                withAnimation(.easeOut(duration: 0.15)) { isOpen.toggle() }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 9, weight: .bold)).foregroundStyle(.secondary)
                        .rotationEffect(.degrees(isOpen ? 90 : 0))
                    IndicatorSectionTitle(title: title, count: entries.count)
                    Spacer(minLength: 0)
                }
                .frame(minHeight: 20)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(help)
            .accessibilityLabel("\(title), \(entries.count)")
            .accessibilityValue(isOpen ? "Shown" : "Hidden")
            if isOpen {
                ForEach(entries) { entry in
                    IndicatorPopoverCard(indicator: entry.indicator, events: entry.events, isCard: true,
                                         isListed: listed.contains(entry.indicator.id), close: close)
                }
            }
        }
    }
}


// MARK: - Card
/// One indicator the event matched: its symbol tile, name, tactic and severity, its description, its predicate, and
/// Show in Settings, or, for one Settings no longer lists, that it was removed. Among several, each is a card.
private struct IndicatorPopoverCard: View {
    let indicator: Indicator
    /// How many events matched it, shown after its name when it's more than one: "Reflective loading ×6".
    var events = 1
    /// Is it a card among several?
    let isCard: Bool
    /// Does Settings > Indicators still list it? One it doesn't has no predicate or place in Settings to show.
    let isListed: Bool
    /// Closes the popover.
    let close: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 8) {
                header
                if !indicator.description.isEmpty {
                    Text(indicator.description)
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if isListed {
                IndicatorPredicateSection(indicator: indicator)
                section {
                    HStack {
                        Spacer(minLength: 0)
                        ShowInSettingsButton(indicator: indicator, then: close)
                    }
                }
            } else {
                section {
                    Text("This indicator was removed from Settings > Indicators.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .padding(isCard ? 12 : 0)
        .background {
            if isCard {
                RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.primary.opacity(0.035))
                RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Color.primary.opacity(0.08))
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(indicator.name)
    }

    /// Its symbol tile, name, tactic and severity.
    private var header: some View {
        HStack(alignment: .center, spacing: 8) {
            SettingsRowIcon(indicator.symbol, indicator.tint, size: 24)
            Text(indicator.title(events)).font(.system(size: 13, weight: .semibold)).lineLimit(2)
            if let tactic = indicator.tactic {
                Text(tactic.name)
                    .font(.system(size: 11, weight: .medium)).foregroundStyle(IndicatorChip.text)
                    .lineLimit(1).fixedSize()
                    .padding(.horizontal, 6).padding(.vertical, 1)
                    .background(IndicatorChip.fill, in: RoundedRectangle(cornerRadius: 4, style: .continuous))
                    .help(tacticHelp(tactic))
                    .accessibilityLabel("Tactic: \(tactic.name)")
            }
            Spacer(minLength: 4)
            IndicatorSeverityBadge(severity: indicator.severity)
        }
    }

    /// - Parameter tactic: Its tactic.
    /// - Returns: The tactic's name and identity, and its technique when it has one: "Execution, TA0002 (T1059)".
    private func tacticHelp(_ tactic: Indicator.Tactic) -> String {
        let technique = indicator.technique.flatMap { $0.isEmpty ? nil : " (\($0))" } ?? ""
        return "\(tactic.name), \(tactic.identifier)\(technique)"
    }

    /// - Parameter content: What the section holds.
    /// - Returns: It under a line, as each section after the description is.
    private func section(@ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Divider()
            content()
        }
    }
}


// MARK: - Show in Settings
/// The Show in Settings link: it asks Settings > Indicators to show the indicator
/// (``IndicatorStore/requestReveal(_:)``), closes the popover, then opens the Settings window, or brings it to the
/// front when it's open.
struct ShowInSettingsButton: View {
    let indicator: Indicator
    /// Closes the popover.
    let then: () -> Void
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button {
            IndicatorStore.shared.requestReveal(indicator.id)
            then()
            openWindow(id: ProjectSutroApp.settingsWindow)
        } label: {
            HStack(spacing: 4) {
                Text("Show in Settings")
                Image(systemName: "arrow.up.right").font(.system(size: 9, weight: .bold))
            }
            .font(.system(size: 12))
            .foregroundStyle(Color.accentColor)
            .frame(minHeight: 24)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Opens Settings > Indicators, scrolled to \(indicator.name)")
        .accessibilityLabel("Show \(indicator.name) in Settings")
    }
}


// MARK: - Severity
/// An indicator's severity as the popover shows it: a capsule with three bars, as many filled as its level, and its
/// name. High is solid red, Medium amber and Low gray, in light and dark.
struct IndicatorSeverityBadge: View {
    let severity: IndicatorSeverity

    /// How many of the three bars are filled.
    private var level: Int {
        switch severity {
        case .high: return 3
        case .medium: return 2
        case .low: return 1
        }
    }

    /// The capsule's color and the text's.
    private var colors: (fill: Color, text: Color) {
        switch severity {
        case .high: return (.appearance(light: .hex(0xC42B21), dark: .hex(0xFF6B60)),
                            .appearance(light: .white, dark: .hex(0x2A0400)))
        case .medium: return (.appearance(light: .hex(0xF6BB5A), dark: .hex(0x8A5A12)),
                              .appearance(light: .hex(0x3D2400), dark: .hex(0xFFE6BF)))
        case .low: return (IndicatorChip.fill, IndicatorChip.text)
        }
    }

    var body: some View {
        HStack(spacing: 4) {
            HStack(alignment: .bottom, spacing: 1) {
                ForEach(Array([4.5, 7.5, 11].enumerated()), id: \.offset) { index, height in
                    RoundedRectangle(cornerRadius: 0.8)
                        .frame(width: 3, height: height)
                        .opacity(index < level ? 1 : 0.3)
                }
            }
            .accessibilityHidden(true)
            Text(severity.name)
        }
        .font(.system(size: 11, weight: .semibold))
        .foregroundStyle(colors.text)
        .padding(.leading, 6).padding(.trailing, 8).padding(.vertical, 2)
        .background(colors.fill, in: Capsule())
        .fixedSize()
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(severity.name) severity")
        .help("\(severity.name) severity")
    }
}


/// The gray of the popover's chips, a tactic's and Low's: its fill and its text, in light and dark.
enum IndicatorChip {
    static let fill = Color.appearance(light: .hex(0xE6E6EB), dark: .white.withAlphaComponent(0.11))
    static let text = Color.appearance(light: .hex(0x3A3A3C), dark: .hex(0xD6D6DA))
}

