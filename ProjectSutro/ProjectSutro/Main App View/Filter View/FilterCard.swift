//
//  FilterCard.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/26/26.
//

import SwiftUI


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
struct FilterCardView: View {
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
