//
//  MuteTableRows.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/26/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Rows
/// A group's header: its mute type's badge, or its event's symbol and name, and how many mutes it has.
struct GroupHeader: View {
    let group: PathMutingSettingsView.Group

    var body: some View {
        HStack(spacing: 8) {
            if let kind = group.kind {
                MuteTypeBadgeView(kind: kind)
                Text(kind.rawValue).font(.caption.monospaced()).foregroundStyle(.secondary)
            } else if let event = group.event {
                Label(event.shortName, systemImage: event.symbol).font(.caption.weight(.semibold))
                Text(event.name).font(.caption.monospaced()).foregroundStyle(.secondary)
            } else {
                Text("All events").font(.caption.weight(.semibold))
                Text("es_mute_path").font(.caption.monospaced()).foregroundStyle(.secondary)
            }
            Spacer()
            Text("\(group.mutes.count) \(group.mutes.count == 1 ? "mute" : "mutes")")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}


/// One mute: its path, then its events (or, grouped by event, its type), unless the inspector shows them.
struct MuteRow: View {
    let mute: ESMutedPath
    let showsEvents: Bool
    let showsKind: Bool

    /// The most events a row names before counting the rest.
    private static let eventsShown = 3

    var body: some View {
        HStack(spacing: 10) {
            Text(mute.path)
                .font(.body.monospaced())
                .lineLimit(1)
                .truncationMode(.middle)
                .help(mute.path)
            Spacer(minLength: 8)
            if showsKind {
                MuteTypeBadgeView(path: mute)
            } else if showsEvents {
                events.frame(width: 250, alignment: .leading)
            }
        }
    }

    /// "All events", or the first few events as tokens and how many more there are.
    @ViewBuilder private var events: some View {
        if mute.events.isEmpty {
            Text("All events").foregroundStyle(.secondary)
        } else {
            HStack(spacing: 4) {
                ForEach(mute.events.prefix(Self.eventsShown), id: \.self) { name in
                    Text(EventCatalog.event(named: name).shortName)
                        .font(.caption.monospaced())
                        .padding(.horizontal, 5).padding(.vertical, 1)
                        .background(.quaternary, in: RoundedRectangle(cornerRadius: 4))
                }
                if mute.events.count > Self.eventsShown {
                    Text("+\(mute.events.count - Self.eventsShown) more").font(.caption).foregroundStyle(.secondary)
                }
            }
            .help(mute.events.map { EventCatalog.event(named: $0).shortName }.joined(separator: ", "))
        }
    }
}
