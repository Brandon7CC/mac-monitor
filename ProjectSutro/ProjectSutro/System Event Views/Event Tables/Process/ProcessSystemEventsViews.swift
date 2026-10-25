//
//  ProcessSystemEventsViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework
import OSLog


/// An exec's process name in the event tables, after what's worth knowing about it, as its Event Facts label shows:
/// root or elevated, a dyld injection, File Quarantine awareness, the findings that mark it
/// (Settings ▸ Findings), such as a new executable or a script, then how it's signed.
struct ProcessExecEventNameView: View {
    var message: ESMessage

    /// Nothing for an exec that's gone, as a Clear's events are while the tables let go of them.
    var body: some View {
        if let exec = message.event.exec {
            name(exec)
        }
    }

    /// - Parameter exec: The exec.
    /// - Returns: Its icons, then its process name, as it's signed.
    private func name(_ exec: ESProcessExecEvent) -> some View {
        let procName = (exec.target.executable?.path ?? "").lastPathComponent
        return HStack {
            indicators(exec)
            if exec.target.is_adhoc_signed {
                Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette)
                    .foregroundStyle(.black, .orange).help("Binary is adhoc signed!")
                Label("**\(procName)**", systemImage: "xmark.seal").symbolRenderingMode(.palette).foregroundStyle(.orange)
            } else if (exec.target.signing_id.nonEmpty ?? "Unknown") == "Unknown" {
                Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette)
                    .foregroundStyle(.black, .red).help("Unknown signing ID")
                Label("**\(procName)**", systemImage: "xmark.seal").symbolRenderingMode(.palette).foregroundStyle(.red)
            } else {
                Label(procName, systemImage: "checkmark.seal")
            }
        }
        .frame(alignment: .leading)
    }

    /// - Parameter exec: The exec.
    /// - Returns: Every exec's icons, whatever its signature.
    @ViewBuilder
    private func indicators(_ exec: ESProcessExecEvent) -> some View {
        if exec.target.ruid == 0 {
            Image(systemName: "person.crop.circle.badge.exclamationmark.fill").symbolRenderingMode(.multicolor)
                .padding([.leading], 2.0).help("Process is running as the root user")
        } else if exec.target.ruid != exec.target.euid && exec.target.euid == 0 {
            Image(systemName: "key.radiowaves.forward.fill").symbolRenderingMode(.multicolor)
                .padding([.leading], 2.0).help("Process elevated to root!")
        }
        if exec.env.joined().lowercased().contains("dyld_insert_libraries") {
            Image(systemName: "bookmark.slash").help("Dyld injection attempt.").symbolRenderingMode(.palette)
                .foregroundStyle(.red)
        }
        /// The process is File Quarantine-aware: `LSFileQuarantineEnabled` in its `Info.plist`.
        if exec.target.file_quarantine_type != "DISABLED" {
            Image(systemName: "lock.icloud").symbolRenderingMode(.multicolor).padding([.leading], 2.0)
                .help("Process is File Quarantine-aware.")
        }
        FindingMarks(message: message)
    }
}


// MARK: – Sortable proxies
extension ESMessage {
    var sortableTimestamp: TimeInterval { message_darwin_time?.timeIntervalSince1970 ?? 0 }
    var sortProcessName:   String       { event.exec?.target.executable?.name ?? "" }
    var sortSigningID:     String       { event.exec?.target.signing_id      ?? "" }
    var sortProcessPath:   String       { event.exec?.target.executable?.path ?? "" }
    var sortCommandLine:   String       { event.exec?.command_line           ?? "" }
    var sortEventType:     String       { es_event_type                      ?? "" }
    var sortRenameDestination: String   { event.rename?.destination_path     ?? "" }
    var sortRenameSource:  String       { event.rename?.source.path          ?? "" }
    var sortCreateTarget:  String       { event.create?.targetPath           ?? "" }
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

    @State private var sortOrder: [KeyPathComparator] = [
        .init(\ESMessage.sortableTimestamp, order: .reverse)
    ]

    private var rows: [ESMessage] { messages.sorted(using: sortOrder) }

    var body: some View {
        Group {
            if simple {
                simpleTable
            } else {
                Section(header: Label("Process", systemImage: "cpu").font(.title2)) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("**Execution**")
                        simpleTable
                    }
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
            ForEach(rows) { msg in
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

    @State private var sortOrder: [KeyPathComparator] = [
        .init(\ESMessage.sortableTimestamp, order: .reverse)
    ]

    private var rows: [ESMessage] { messages.sorted(using: sortOrder) }

    var body: some View {
        Group {
            if simple {
                simpleTable
            } else {
                Section(header: Label("Process", systemImage: "cpu").font(.title2)) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("**Execution**")
                        simpleTable
                    }
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
            ForEach(rows) { msg in
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
    }
}
