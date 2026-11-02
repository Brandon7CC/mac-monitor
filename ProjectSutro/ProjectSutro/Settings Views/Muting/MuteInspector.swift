//
//  MuteInspector.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/26/26.
//

import SwiftUI
import AppKit
import SutroESFramework


// MARK: - Inspector
/// The selected mute beside the table: its type, its whole path, every event it covers with a way to unmute each,
/// and Unmute Path.
struct MuteInspector: View {
    let mute: ESMutedPath
    let canEdit: Bool
    let close: () -> Void
    let unmute: (ESMutedPath, [String]) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                MuteTypeBadgeView(path: mute)
                Spacer()
                Button(action: close) {
                    Image(systemName: "xmark.circle.fill").symbolRenderingMode(.palette)
                        .foregroundStyle(.white, .red)
                }
                .buttonStyle(.borderless)
                .help("Close")
                .accessibilityLabel("Close the details")
                .keyboardShortcut(.cancelAction)
            }
            .padding(10)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(mute.path).font(.callout.monospaced()).textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                    if mute.events.isEmpty {
                        Text("Muted for every event").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                        Text("To mute only some events, unmute the path, then add it back for those events.")
                            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    } else {
                        Text("Muted for \(mute.events.count) \(mute.events.count == 1 ? "event" : "events")")
                            .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                        VStack(spacing: 0) {
                            ForEach(Array(mute.events.enumerated()), id: \.element) { index, name in
                                if index > 0 { Divider() }
                                eventRow(name)
                            }
                        }
                        .background(.background, in: RoundedRectangle(cornerRadius: 8))
                        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(.separator))
                    }
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            Divider()
            Button(role: .destructive) { unmute(mute, []) } label: {
                Label("Unmute Path", systemImage: "speaker.wave.2.fill").frame(maxWidth: .infinity)
            }
            .foregroundStyle(.red)
            .disabled(!canEdit)
            .padding(10)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    /// One event the mute covers, and its Unmute button.
    ///
    /// - Parameter name: The event's `ES_EVENT_TYPE_*` name.
    /// - Returns: The row.
    private func eventRow(_ name: String) -> some View {
        let event = EventCatalog.event(named: name)
        return HStack(spacing: 8) {
            Image(systemName: event.symbol).foregroundStyle(.secondary).frame(width: 18)
            Text(event.shortName).font(.callout.monospaced()).help(event.name)
            Spacer()
            Button { unmute(mute, [name]) } label: {
                Label("Unmute", systemImage: "speaker.wave.2.fill").font(.caption.weight(.semibold))
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .foregroundStyle(.red)
            .disabled(!canEdit)
            .accessibilityLabel("Unmute \(event.title)")
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
    }
}
