//
//  ProcessSystemEventsViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework

// MARK: – Sortable proxies
extension ESMessage {
    var sortProcessName:   String       { event.exec?.target.executable?.name ?? "" }
    var sortSigningID:     String       { event.exec?.target.signing_id      ?? "" }
    var sortProcessPath:   String       { event.exec?.target.executable?.path ?? "" }
    var sortCommandLine:   String       { event.exec?.command_line           ?? "" }
}

// MARK: - Ventura Process Table
struct SystemProcessExecTableView: View {
    @EnvironmentObject private var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject private var userPrefs: UserPrefs
    @Environment(\.openWindow) private var openEventJSON

    var messages: [ESMessage]
    var simple: Bool = false
    @Binding var messageSelections: Set<ESMessage.ID>
    @Binding var allFilters: Filters
    @Binding var ascending: Bool

    @State private var sortOrder: [KeyPathComparator] = [
        .init(\ESMessage.sortableTimestamp, order: .reverse)
    ]

    /// Whether the user has explicitly changed the sort order from the default.
    /// When false, input data is already pre-sorted (reverse-chronological) and
    /// we skip the O(n log n) sort entirely — matching ProcMon's no-sort approach.
    @State private var needsExplicitSort: Bool = false

    private var rows: [ESMessage] {
        if !needsExplicitSort { return messages }
        return messages.sorted(using: sortOrder)
    }

    private var displayedRows: [ESMessage] {
        if needsExplicitSort { return rows }
        return Array(rows.reversed())
    }

    var body: some View {
        Group {
            if simple {
                simpleTable
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Process", systemImage: "cpu")
                        .font(.title2)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Text("**Execution**")
                    simpleTable
                }
            }
        }
    }

    private var simpleTable: some View {
        Table(of: ESMessage.self,
              selection: $messageSelections,
              sortOrder: $sortOrder
        ) {
            TableColumn("Timestamp",
                                    value: \.sortableTimestamp) { m in
                Text("`\(eventTimeStamp(for: m))`")
            }
            .width(min: 100, ideal: 100, max: 100)
            
            TableColumn("Process name",
                        value: \.sortProcessName) { m in
                ProcessExecEventNameView(message: m)
            }.width(min: 80, ideal: 100, max: 400)

            TableColumn("Signing ID",
                        value: \.sortSigningID) { m in
                Text("`\(m.event.exec?.target.signing_id ?? "")`")
            }.width(min: 80, ideal: 100, max: 200)

            TableColumn("Process path",
                        value: \.sortProcessPath) { m in
                Text("`\(m.sortProcessPath)`")
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }.width(min: 50, ideal: 60, max: 300)

            TableColumn("Command line",
                        value: \.sortCommandLine) { m in
                Text("`\(m.sortCommandLine)`")
                    .lineLimit(8)
                    .textSelection(.enabled)
            }.width(min: 200, ideal: 600, max: .infinity)
        } rows: {
            ForEach(displayedRows) { msg in
                TableRow(msg).contextMenu {
                    if msg.event.exec != nil {
                        TableExecEventContextMenu(allFilters: $allFilters, message: msg)
                            .environmentObject(systemExtensionManager)
                            .environmentObject(userPrefs)
                    } else {
                        TableNonExecContextMenus(allFilters: $allFilters, message: msg)
                            .environmentObject(systemExtensionManager)
                            .environmentObject(userPrefs)
                    }
                }
            }
        }
        .onChange(of: sortOrder) { _ in
            needsExplicitSort = true
        }
    }
}


// MARK: - macOS 14+ Process Table
@available(macOS 14.0, *)
struct CustomizableSystemProcessExecTableView: View {
    @SceneStorage("ProcessExecTableConfig")
    private var columnCustomization: TableColumnCustomization<ESMessage>

    @EnvironmentObject private var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject private var userPrefs: UserPrefs
    @Environment(\.openWindow) private var openEventJSON

    var messages: [ESMessage]
    var simple: Bool = false
    @Binding var messageSelections: Set<ESMessage.ID>
    @Binding var allFilters: Filters
    @Binding var ascending: Bool

    @State private var sortOrder: [KeyPathComparator] = [
        .init(\ESMessage.sortableTimestamp, order: .reverse)
    ]

    /// Whether the user has explicitly changed the sort order from the default.
    /// When false, input data is already pre-sorted (reverse-chronological) and
    /// we skip the O(n log n) sort entirely — matching ProcMon's no-sort approach.
    @State private var needsExplicitSort: Bool = false

    private var rows: [ESMessage] {
        if !needsExplicitSort { return messages }
        return messages.sorted(using: sortOrder)
    }

    private var displayedRows: [ESMessage] {
        if needsExplicitSort { return rows }
        return Array(rows.reversed())
    }

    var body: some View {
        Group {
            if simple {
                simpleTable
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Process", systemImage: "cpu")
                        .font(.title2)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Text("**Execution**")
                    simpleTable
                }
            }
        }
    }

    private var simpleTable: some View {
        Table(of: ESMessage.self,
              selection: $messageSelections,
              sortOrder: $sortOrder,
              columnCustomization: $columnCustomization) {
            TableColumn("Timestamp",
                        value: \.sortableTimestamp) { m in
                Text("`\(eventTimeStamp(for: m))`")
            }
            .width(min: 100, ideal: 100, max: 100)
            .customizationID("Timestamp")
            .defaultVisibility(.hidden)
            
            
            TableColumn("Process name",
                        value: \.sortProcessName) { m in
                ProcessExecEventNameView(message: m)
            }
            .width(min: 80, ideal: 100, max: 400)
            .customizationID("Process name")
            .disabledCustomizationBehavior(.visibility)

            TableColumn("Signing ID",
                        value: \.sortSigningID) { m in
                Text("`\(m.sortSigningID)`")
            }
            .width(min: 80, ideal: 100, max: 200)
            .customizationID("Signing ID")

            TableColumn("Process path",
                        value: \.sortProcessPath) { m in
                Text("`\(m.sortProcessPath)`")
                    .textSelection(.enabled)
                    .truncationMode(.middle)
            }
            .width(min: 50, ideal: 60, max: 300)
            .customizationID("Process path")

            TableColumn("Command line",
                        value: \.sortCommandLine) { m in
                Text("`\(m.sortCommandLine)`")
                    .lineLimit(8)
                    .textSelection(.enabled)
            }
            .width(min: 200, ideal: 600, max: .infinity)
            .customizationID("Command line")
            .disabledCustomizationBehavior(.visibility)
        } rows: {
            ForEach(displayedRows) { msg in
                TableRow(msg).contextMenu {
                    if msg.event.exec != nil {
                        TableExecEventContextMenu(allFilters: $allFilters, message: msg)
                            .environmentObject(systemExtensionManager)
                            .environmentObject(userPrefs)
                    } else {
                        TableNonExecContextMenus(allFilters: $allFilters, message: msg)
                            .environmentObject(systemExtensionManager)
                            .environmentObject(userPrefs)
                    }
                }
            }
        }
        .onChange(of: sortOrder) { _ in
            needsExplicitSort = true
        }
    }
}
