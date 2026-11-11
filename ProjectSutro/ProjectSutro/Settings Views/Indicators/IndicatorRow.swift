//
//  IndicatorRow.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/8/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Rows
/// One indicator, as Subscriptions draws an event (``SettingsItemRow``): its symbol, in its color while it's on, its
/// name and severity, its technique and how it marks the tables, why the Security Extension can't run it if it
/// can't, a crossed-out bell when this user said not to notify for it, an Edit button, and its switch, which is
/// off-limits while the Mac's indicators can't be changed. Clicking the row edits it too. Its description is its
/// help.
struct IndicatorRow: View {
    let indicator: Indicator
    /// Why the Security Extension can't run it, or `nil`.
    let sensorProblem: String?
    /// May the Mac's indicators be changed?
    let canChange: Bool
    /// Did this user say not to notify for it?
    var silenced = false
    /// Keeps a change to its switch.
    let save: (Indicator) -> Void
    let edit: () -> Void

    var body: some View {
        SettingsItemRow(title: indicator.name, symbol: indicator.symbol, tint: indicator.tint,
                        switchLabel: "Look for \(indicator.name)", isOn: Binding { indicator.isEnabled } set: { on in
            var changed = indicator
            changed.isEnabled = on
            save(changed)
        }, canSwitch: canChange, open: edit) {
            SeverityBadge(severity: indicator.severity)
            if silenced {
                Image(systemName: "bell.slash").foregroundStyle(.secondary)
                    .help("Doesn't notify you")
                    .accessibilityLabel("Doesn't notify you")
            }
            if sensorProblem != nil {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    .accessibilityHidden(true)
            }
        } details: {
            HStack(spacing: 6) {
                if let technique = indicator.technique, !technique.isEmpty {
                    Text(technique).font(.caption.monospaced())
                }
                Text(indicator.tableMarks.isEmpty ? "Not marked in tables" : indicator.tableMarks.title + " in tables")
                    .font(.caption)
            }
            .foregroundStyle(.secondary)
            .lineLimit(1)
            if let sensorProblem {
                Text("Not run by the Security Extension: \(sensorProblem)")
                    .font(.caption).foregroundStyle(.orange).lineLimit(2)
            }
        } accessory: {
            Button(action: edit) { Image(systemName: "square.and.pencil") }
                .buttonStyle(.link)
                .help("Edit \(indicator.name)")
                .accessibilityLabel("Edit \(indicator.name)")
        }
        .help(indicator.description.isEmpty ? "Edit \(indicator.name)" : indicator.description)
    }
}


/// An indicator's severity, as a small capsule: High in red, Medium in orange, Low in gray.
struct SeverityBadge: View {
    let severity: IndicatorSeverity

    var body: some View {
        Text(severity.name)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(severity.tint)
            .padding(.horizontal, 5).padding(.vertical, 1)
            .background(severity.tint.opacity(0.15), in: Capsule())
            .accessibilityLabel("\(severity.name) severity")
            .help("\(severity.name) severity")
    }
}


extension IndicatorSeverity {
    /// Its color, as AppKit draws it: red for High, orange for Medium, gray for Low. An event's dot in the tables
    /// takes it.
    var nsColor: NSColor {
        switch self {
        case .high: return .systemRed
        case .medium: return .systemOrange
        case .low: return .systemGray
        }
    }

    /// Its badge's color, the same as its dot's.
    var tint: Color { Color(nsColor: nsColor) }
}


/// A menu of the ATT&CK tactics, with each one's identity, and None.
struct TacticPicker: View {
    @Binding var tactic: Indicator.Tactic?

    var body: some View {
        Picker("Tactic", selection: $tactic) {
            Text("None").tag(Indicator.Tactic?.none)
            Divider()
            ForEach(Indicator.Tactic.allCases, id: \.self) { tactic in
                Text("\(tactic.name)  \(tactic.identifier)").tag(Indicator.Tactic?.some(tactic))
            }
        }
        .pickerStyle(.menu)
    }
}


extension IndicatorScope {
    /// Its row's SF Symbol.
    var symbol: String {
        switch self {
        case .all: return "sparkle.magnifyingglass"
        case .tactic(let tactic): return tactic.symbol
        case .noTactic: return "questionmark"
        case .off: return "power"
        case .symbol: return "tablecells"
        }
    }

    /// Its row's color.
    var tint: Color {
        switch self {
        case .all: return .orange
        case .tactic(let tactic): return tactic.tint
        case .noTactic, .off: return .gray
        case .symbol: return .blue
        }
    }
}


extension Indicator.Tactic {
    /// Its tile's SF Symbol.
    var symbol: String {
        switch self {
        case .reconnaissance: return "binoculars.fill"
        case .resourceDevelopment: return "hammer.fill"
        case .initialAccess: return "door.left.hand.open"
        case .execution: return "play.fill"
        case .persistence: return "pin.fill"
        case .privilegeEscalation: return "arrow.up.circle.fill"
        case .defenseEvasion: return "eye.slash.fill"
        case .credentialAccess: return "key.fill"
        case .discovery: return "magnifyingglass"
        case .lateralMovement: return "arrow.left.arrow.right"
        case .collection: return "tray.full.fill"
        case .commandAndControl: return "antenna.radiowaves.left.and.right"
        case .exfiltration: return "arrow.up.doc.fill"
        case .impact: return "bolt.fill"
        }
    }

    /// Its tile's color.
    var tint: Color {
        switch self {
        case .reconnaissance, .resourceDevelopment: return .gray
        case .initialAccess: return .teal
        case .execution: return .purple
        case .persistence: return .green
        case .privilegeEscalation: return .red
        case .defenseEvasion: return .indigo
        case .credentialAccess: return .blue
        case .discovery: return .cyan
        case .lateralMovement: return .mint
        case .collection: return .brown
        case .commandAndControl: return .orange
        case .exfiltration: return .pink
        case .impact: return .red
        }
    }
}
