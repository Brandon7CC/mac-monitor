//
//  UnifiedSystemEventViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework
import OSLog


// MARK: – Sortable proxies
extension ESMessage {
    var sortableTimestamp: TimeInterval { message_darwin_time.timeIntervalSince1970 }
    var sortEffectiveUser: String       { process.euid_human       ?? "" }
    var sortSourceProcess: String       { process.executable?.name ?? "" }
    var sortSourceSigningID: String     { process.signing_id       ?? "" }
    var sortSourceProcessPath: String { process.executable?.path ?? "" }
    
    var sortEventType: String {
        es_event_type
    }

    var sortContext: String {
        context ?? ""
    }
}


// MARK: - Sonoma+ unified table
@available(macOS 14.0, *)
struct CustomizableUnifiedSystemEventsTableView: View {
    @SceneStorage("UnifiedSystemTableConfig")
    private var columnCustomization: TableColumnCustomization<ESMessage>

    @EnvironmentObject private var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject private var userPrefs: UserPrefs
    @Environment(\.openWindow) private var openEventJSON

    @Binding var allFilters: Filters
    var messagesInScope: [ESMessage]

    @Binding var messageSelections: Set<ESMessage.ID>
    @Binding var ascending: Bool

    @State private var sortOrder: [KeyPathComparator] = [
        .init(\ESMessage.sortableTimestamp, order: .reverse)
    ]

    /// Whether the user has explicitly changed the sort order from the default.
    /// When false, input data is already pre-sorted (reverse-chronological) and
    /// we skip the O(n log n) sort entirely — matching ProcMon's no-sort approach.
    @State private var needsExplicitSort: Bool = false

    private var rows: [ESMessage] {
        if !needsExplicitSort { return messagesInScope }
        return messagesInScope.sorted(using: sortOrder)
    }

    private var displayedRows: [ESMessage] {
        if needsExplicitSort { return rows }
        return Array(rows.reversed())
    }

    var body: some View {
        Table(of: ESMessage.self,
              selection: $messageSelections,
              sortOrder: $sortOrder,
              columnCustomization: $columnCustomization)
        {
            TableColumn("Timestamp",
                        value: \.sortableTimestamp) { event in
                Text("`\(eventTimeStamp(for: event))`")
            }
            .width(min: 100, ideal: 100, max: 100)
            .customizationID("Timestamp")

            TableColumn("Event type",
                        value: \.sortEventType) { event in
                SystemEventTypeLabel(message: event)
                    .truncationMode(.middle)
            }
            .width(min: 150, ideal: 200, max: 400)
            .customizationID("Event type")
            .disabledCustomizationBehavior(.visibility)

            TableColumn("Context",
                        value: \.sortContext) { event in
                Text("`\(event.context ?? "")`")
                    .truncationMode(.middle)
            }
            .width(min: 100, ideal: 150, max: 2_000)
            .customizationID("Context")
            .disabledCustomizationBehavior(.visibility)

            TableColumn("Effective user",
                        value: \.sortEffectiveUser) { event in
                Text("`\(event.process.euid_human ?? "")`")
            }
            .width(min: 80, ideal: 90, max: 120)
            .customizationID("Effective user")

            TableColumn("Source process",
                        value: \.sortSourceProcess) { event in
                Text("`\(event.process.executable?.name ?? "")`")
            }
            .width(min: 80, ideal: 100, max: 200)
            .customizationID("Source process")

            TableColumn("Initiating pid",
                        value: \.process.pid) { event in
                Text("`\(String(event.process.pid))`")
            }
            .width(min: 30, ideal: 50, max: 80)
            .customizationID("Initiating pid")
            .defaultVisibility(.hidden)

            TableColumn("ppid",
                        value: \.process.ppid) { event in
                Text("`\(String(event.process.ppid))`")
            }
            .width(min: 20, ideal: 30, max: 50)
            .customizationID("ppid")
            .defaultVisibility(.hidden)

            TableColumn("Source process path",
                        value: \.sortSourceProcessPath) { event in
                Text("`\(event.process.executable?.path ?? "")`")
                    .truncationMode(.middle)
            }
            .width(min: 50, ideal: 200, max: 500)
            .customizationID("Source process path")
            .defaultVisibility(.hidden)


            TableColumn("Source Signing ID",
                        value: \.sortSourceSigningID) { event in
                Text("`\(event.process.signing_id ?? "")`")
            }
            .width(min: 80, ideal: 100, max: 200)
            .customizationID("Source Signing ID")
        } rows: {
            ForEach(displayedRows) { msg in
                TableRow(msg)
                    .contextMenu {
                        if msg.event.exec != nil {
                            TableExecEventContextMenu(allFilters: $allFilters,
                                                      message: msg)
                        } else {
                            TableNonExecContextMenus(allFilters: $allFilters,
                                                     message: msg)
                        }
                    }
            }
        }
        .onChange(of: sortOrder) { _ in
            needsExplicitSort = true
        }
    }
}



// MARK: - Ventura unified table
struct UnifiedSystemEventsTableView: View {
    @EnvironmentObject private var systemExtensionManager: EndpointSecurityManager
    @EnvironmentObject private var userPrefs: UserPrefs
    @Environment(\.openWindow) private var openEventJSON

    @Binding var allFilters: Filters
    var messagesInScope: [ESMessage]

    @Binding var messageSelections: Set<ESMessage.ID>
    @Binding var ascending: Bool

    @State private var sortOrder: [KeyPathComparator] = [
        .init(\ESMessage.sortableTimestamp, order: .reverse)
    ]

    /// Whether the user has explicitly changed the sort order from the default.
    /// When false, input data is already pre-sorted (reverse-chronological) and
    /// we skip the O(n log n) sort entirely — matching ProcMon's no-sort approach.
    @State private var needsExplicitSort: Bool = false

    private var rows: [ESMessage] {
        if !needsExplicitSort { return messagesInScope }
        return messagesInScope.sorted(using: sortOrder)
    }

    private var displayedRows: [ESMessage] {
        if needsExplicitSort { return rows }
        return Array(rows.reversed())
    }

    var body: some View {
        Table(of: ESMessage.self,
              selection: $messageSelections,
              sortOrder: $sortOrder)
        {
            TableColumn("Timestamp",
                        value: \.sortableTimestamp) { event in
                Text("`\(eventTimeStamp(for: event))`")
            }.width(min: 100, ideal: 100, max: 100)

            TableColumn("Event type",
                        value: \.sortEventType) { event in
                SystemEventTypeLabel(message: event)
                    .truncationMode(.middle)
            }.width(min: 150, ideal: 200, max: 400)

            TableColumn("Context",
                        value: \.sortContext) { event in
                Text("`\(event.context ?? "")`")
                    .truncationMode(.middle)
            }.width(min: 100, ideal: 150, max: 2_000)

            TableColumn("Effective user",
                        value: \.sortEffectiveUser) { event in
                Text("`\(event.process.euid_human ?? "Unknown")`")
            }.width(min: 80, ideal: 90, max: 120)

            TableColumn("Source process",
                        value: \.sortSourceProcess) { event in
                Text("`\(event.process.executable?.name ?? "")`")
            }.width(min: 80, ideal: 100, max: 200)

            TableColumn("Source Signing ID",
                        value: \.sortSourceSigningID) { event in
                Text("`\(event.process.signing_id ?? "")`")
            }.width(min: 80, ideal: 100, max: 200)
        } rows: {
            ForEach(displayedRows) { msg in
                TableRow(msg)
                    .contextMenu {
                        if msg.event.exec != nil {
                            TableExecEventContextMenu(allFilters: $allFilters,
                                                      message: msg)
                                .environmentObject(systemExtensionManager)
                                .environmentObject(userPrefs)
                        } else {
                            TableNonExecContextMenus(allFilters: $allFilters,
                                                     message: msg)
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


