//
//  EventDetailsBox.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/25/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Details box
/// Event Facts' Details section: an event's details in one box, a network flow's facts above them, then a tab at a
/// time. A segmented control picks the tab when there's more than one, each titled with its count. The tab picked last
/// shows on every event that has it, and the first tab shows on one that doesn't.
struct EventDetailsBox: View {
    /// The details.
    let details: EventDetails
    /// The tab picked last, or `nil` before one is picked.
    @AppStorage("eventFactsDetailsTab") private var picked: EventDetails.Tab?
    /// The Environment tab's filter text. It's kept here, so it lasts while another tab shows.
    @State private var environmentFilter = ""
    /// Does the Environment tab show every matching row?
    @State private var showsAllEnvironment = false

    /// Nothing when there are no details.
    var body: some View {
        let tabs = details.tabs
        if !details.isEmpty {
            Divider()
            Label("**Details**", systemImage: "list.bullet.rectangle").font(.title2).padding(.leading, 5)
            FactsBox {
                ForEach(details.facts) { fact in FactRow { EventFactView(fact: fact) } }
                if let shown = details.shownTab(picked: picked) {
                    if tabs.count > 1 {
                        picker(tabs, Binding { shown } set: { picked = $0 })
                    }
                    content(shown)
                }
            }
        }
    }

    /// The tabs as a segmented control, or as a menu when the segments don't fit.
    ///
    /// - Parameters:
    ///   - tabs: The event's tabs.
    ///   - selection: The tab showing.
    /// - Returns: The control, centered.
    private func picker(_ tabs: [EventDetails.Tab], _ selection: Binding<EventDetails.Tab>) -> some View {
        let picker = Picker("Details", selection: selection) {
            ForEach(tabs) { Text("\($0.rawValue) \(details.count(of: $0))").tag($0) }
        }.labelsHidden().fixedSize()
        return ViewThatFits(in: .horizontal) {
            picker.pickerStyle(.segmented)
            picker.pickerStyle(.menu)
        }
        .frame(maxWidth: .infinity)
        .padding(.bottom, 4)
    }

    /// A tab's content.
    ///
    /// - Parameter tab: The tab.
    /// - Returns: Its view.
    @ViewBuilder
    private func content(_ tab: EventDetails.Tab) -> some View {
        switch tab {
        case .environment:
            EnvironmentTable(variables: details.environment, filter: $environmentFilter,
                             showsAll: $showsAllEnvironment)
        case .auditTokens:
            ForEach(details.auditTokens) { FactRow(name: $0.name, value: $0.token, stacked: true) }
        case .codeSigningFlags:
            GroupBox {
                FactsGrid(details.codeSigningFlags, columns:
                    .init("Flag") { $0.name },
                    .init("Bit") { String(format: "0x%08X", $0.bit) },
                    .init("Meaning", monospaced: false) { $0.summary })
            }
        case .fileDescriptors:
            GroupBox {
                FactsGrid(details.fileDescriptors, columns:
                    .init("FD") { $0.fd.description },
                    .init("Type") { $0.type },
                    .init("Pipe ID") { $0.pipe?.pipe_id.description ?? "" })
            }
        }
    }
}
