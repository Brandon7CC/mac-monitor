//
//  SystemEnrichedEventView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/18/22.
//

import SwiftUI
import OSLog
import SutroESFramework


@available(macOS 14, *)
struct CustomizableSystemEnrichedTableView: View {
    @SceneStorage("SystemEnrichedTableConfig")
    private var columnCustomization: TableColumnCustomization<ESMessage>
    
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.openWindow) private var openEventJSON
    
    @EnvironmentObject var userPrefs: UserPrefs
    
    var eventsInScope: [ESMessage]
    @State private var unifiedEventSelection = Set<Message.ID>()
    
    
    @Binding var allFilters: Filters
    
    var body: some View {
        Table(of: ESMessage.self, selection: $unifiedEventSelection, columnCustomization: $columnCustomization) {
            TableColumn("Timestamp") { event in
                Text("`\(eventTimeStamp(for: event))`")
            }
            .width(min: 100, ideal: 100, max: 100)
            .customizationID("Timestamp")
            
            TableColumn("Event type") { event in
                SystemEventTypeLabel(message: event)
            }
            .width(min: 150, ideal: 200, max: 300)
            .customizationID("Event type")
            .disabledCustomizationBehavior(.visibility)
            
            TableColumn("Context") { event in
                Text(event.context!)
            }
            .width(min: 80, ideal: 200, max: 2000)
            .customizationID("Context")
            
            TableColumn("Source Process path") { event in
                let path = event.process.executable?.path ?? ""
                Text("`\(path)`")
            }
            .width(min: 50, ideal: 200, max: 2000)
            .customizationID("Source Process path")
            .defaultVisibility(.hidden)
            
            TableColumn("Source Signing ID") { event in
                Text(event.process.signing_id ?? "")
            }
            .width(min: 80, ideal: 100, max: 200)
            .customizationID("Source Signing ID")
        } rows: {
            ForEach(eventsInScope) { (message: ESMessage) in
                TableRow(message).contextMenu {
                    if message.event.exec != nil {
                        TableExecEventContextMenu(allFilters: $allFilters, message: message)
                            .environmentObject(systemExtensionManager)
                            .environmentObject(userPrefs)
                    } else {
                        TableNonExecContextMenus(allFilters: $allFilters, message: message)
                            .environmentObject(systemExtensionManager)
                            .environmentObject(userPrefs)
                    }
                }
              }
        }
    }
}



struct SystemEnrichedTableView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.openWindow) private var openEventJSON
    
    @EnvironmentObject var userPrefs: UserPrefs
    
    var eventsInScope: [ESMessage]
    @State private var unifiedEventSelection = Set<Message.ID>()
    
    
    @Binding var allFilters: Filters
    
    var body: some View {
        Table(of: ESMessage.self, selection: $unifiedEventSelection) {
            TableColumn("Timestamp") { event in
                Text("`\(eventTimeStamp(for: event))`")
            }.width(min: 100, ideal: 100, max: 100)
            TableColumn("Event type") { event in
                SystemEventTypeLabel(message: event)
            }.width(min: 150, ideal: 200, max: 300)
            TableColumn("Context") { event in
                Text(event.context!)
            }.width(min: 80, ideal: 200, max: 2000)
            TableColumn("Source Signing ID") { event in
                Text(event.process.signing_id ?? "")
            }.width(min: 80, ideal: 100, max: 200)
        } rows: {
            ForEach(eventsInScope) { message in
                TableRow(message).contextMenu {
                    if message.event.exec != nil {
                        TableExecEventContextMenu(allFilters: $allFilters, message: message)
                            .environmentObject(systemExtensionManager)
                            .environmentObject(userPrefs)
                    } else {
                        TableNonExecContextMenus(allFilters: $allFilters, message: message)
                            .environmentObject(systemExtensionManager)
                            .environmentObject(userPrefs)
                    }
                }
              }
        }
    }
}


struct SystemRCCorrelatedEventsView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    
    @EnvironmentObject var userPrefs: UserPrefs
    
    var correlatedEvents: [ESMessage]
    
    @Binding var allFilters: Filters
    
    @State private var eventSelection = Set<Message.ID>()
    
    private var forkEvents: [ESMessage] {
        correlatedEvents.filter { $0.event.fork != nil }
    }
    private var childProcs: [ESMessage] {
        forkEvents
            .filter({ forkMsg in
                !systemExtensionManager.eventStore.getCorrelatedEvents(for: forkMsg)
                    .filter({ $0.event.exec != nil }).isEmpty
            })
    }
    private var fileEvents: [ESMessage] {
        correlatedEvents.filter({ $0.event.create != nil })
    }
    private var memoryEvents: [ESMessage] {
        correlatedEvents.filter { $0.event.mmap != nil }
    }
    private var fileMetadataEvents: [ESMessage] {
        correlatedEvents.filter({ $0.event.deleteextattr != nil })
    }
    private var launchItemEvents: [ESMessage] {
        correlatedEvents.filter { $0.event.btm_launch_item_add != nil }
    }
    private var launchItemRemoveEvents: [ESMessage] {
        correlatedEvents.filter { $0.event.btm_launch_item_remove != nil }
    }
    private var xprotectEvents: [ESMessage] {
        correlatedEvents
            .filter {
                $0.event.xp_malware_detected != nil || $0.event.xp_malware_remediated != nil
            }
    }
    private var mountEvents: [ESMessage] {
        correlatedEvents.filter { $0.event.mount != nil }
    }
    private var fileDuplicateEvents: [ESMessage] {
        correlatedEvents.filter { $0.event.dup != nil }
    }
    private var fileRenameEvents: [ESMessage] {
        correlatedEvents.filter { $0.event.rename != nil }
    }
    private var loginEvents: [ESMessage] {
        correlatedEvents
            .filter {
                $0.event.login_login != nil || $0.event.lw_session_login != nil || $0.event.openssh_login != nil
            }
    }
    private var logoutEvents: [ESMessage] {
        correlatedEvents.filter { $0.event.openssh_logout != nil }
    }
    
    @State private var hideChildProcs: Bool = true
    @State private var hideFileCreate: Bool = true
    @State private var hideFileRename: Bool = true
    @State private var hideFileDuplicate: Bool = true
    @State private var hideMemoryMappings: Bool = true
    @State private var hideFileMetadata: Bool = true
    @State private var hideBackgroundItems: Bool = true
    @State private var hideXProtectEvents: Bool = true
    @State private var hideLoginEvents: Bool = true
    @State private var hideLogoutEvents: Bool = true
    
    // TODO: When adding suppport for new ES events an appropriate correlated view might make sense
    var body: some View {
        if !loginEvents.isEmpty {
            
            Divider()
            Section {
                HStack {
                    Text("**Login events (\(loginEvents.count))**")
                    Spacer()
                    Button(hideLoginEvents ? "Show" : "Hide") {
                        withAnimation {
                            hideLoginEvents.toggle()
                        }
                    }
                }
                if !hideLoginEvents {
                    SystemLoginEventTableView(loginEvents: loginEvents, eventSelection: $eventSelection, allFilters: $allFilters)
                        .environmentObject(userPrefs)
                }
            }
        }
        
        // MARK: File modifications (NOTIFY_CREATE)
        if fileEvents.count > 0 {
            // MARK: Event introspection
            let dangerousFiles: Int = 0
            let totalNonQuarantinedFiles: Int = fileEvents.filter({ $0.event.create != nil && $0.event.create!.is_quarantined == 0 }).count + fileRenameEvents.filter(
                { $0.event.rename != nil && $0.event.rename!.is_quarantined == 0
                }).count + dangerousFiles
            
            Divider()
            Section {
                HStack {
                    if totalNonQuarantinedFiles > 0 {
                        Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .orange).help("\(totalNonQuarantinedFiles) files are not quarantined")
                    }
                    
                    Text("**File creations (\(fileEvents.count))**")
                    Spacer()
                    Button(hideFileCreate ? "Show" : "Hide") {
                        withAnimation {
                            hideFileCreate.toggle()
                        }
                    }
                }
                if !hideFileCreate {
                    SystemFileEventTableView(fileEvents: fileEvents, eventSelection: $eventSelection, allFilters: $allFilters)
                        .environmentObject(systemExtensionManager)
                        .environmentObject(userPrefs)
                        .textSelection(.enabled)
                }
            }
        }
        
        // MARK: File modifications (NOTIFY_RENAME)
        if fileRenameEvents.count > 0 {
            Divider()
            Section {
                HStack {
                    Text("**File renames (\(fileRenameEvents.count))**")
                    Spacer()
                    Button(hideFileRename ? "Show" : "Hide") {
                        withAnimation {
                            hideFileRename.toggle()
                        }
                    }
                }
                if !hideFileRename {
                    SystemFileRenameEventTableView(fileEvents: fileRenameEvents, eventSelection: $eventSelection, allFilters: $allFilters)
                        .environmentObject(systemExtensionManager)
                        .environmentObject(userPrefs)
                        .textSelection(.enabled)
                }
            }
        }
        
        
        // MARK: File modifications (NOTIFY_MMAP)
        if memoryEvents.count > 0 {
            Divider()
            Section {
                HStack {
                    if memoryEvents.first(where: { pathIsOSAComponent(filePath: $0.event.mmap!.source.path) }) != nil {
                        Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .orange).help("Process mapped an OSA (Open Scripting Architecture) component into memory")
                    }
                    
                    Text("**Memory mappings (\(memoryEvents.count))**")
                    Spacer()
                    Button(hideMemoryMappings ? "Show" : "Hide") {
                        withAnimation {
                            hideMemoryMappings.toggle()
                        }
                    }
                }
                if !hideMemoryMappings {
                    SystemMMAPEventTableView(mmapEvents: memoryEvents, eventSelection: $eventSelection, allFilters: $allFilters, simple: true)
                        .environmentObject(userPrefs)
                }
            }
        }
        
        // MARK: xattr events (NOTIFY_DELETE_XATTR, etc.)
        if fileMetadataEvents.count > 0 {
            Divider()
            Section {
                HStack {
                    Text("**Extended attributes (\(fileMetadataEvents.count))**")
                    Spacer()
                    Button(hideFileMetadata ? "Show" : "Hide") {
                        withAnimation {
                            hideFileMetadata.toggle()
                        }
                    }
                }
                if !hideFileMetadata {
                    SystemFileMetadataEventTableViews(eventsInScope: fileMetadataEvents, eventSelection: $eventSelection, allFilters: $allFilters)
                        .environmentObject(userPrefs)
                        .textSelection(.enabled)
                }
            }
        }
        
        // MARK: Service Management Framework background items (ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD)
        if launchItemEvents.count > 0 {
            Divider()
            Section {
                HStack {
                   Text("**Background Items (\(launchItemEvents.count))**")
                    Spacer()
                    Button(hideBackgroundItems ? "Show" : "Hide") {
                        withAnimation {
                            hideBackgroundItems.toggle()
                        }
                    }
                }
                if !hideBackgroundItems {
                    SystemLaunchItemEventTableView(launchItemEvents: launchItemEvents, eventSelection: $eventSelection, allFilters: $allFilters)
                        .environmentObject(userPrefs)
                }
            }
        }
        
        // MARK: XProtect malware events (ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED or ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED)
        if xprotectEvents.count > 0 {
            Divider()
            Section {
                HStack {
                    Text("**XProtect events (\(xprotectEvents.count))**")
                    Spacer()
                    Button(hideXProtectEvents ? "Show" : "Hide") {
                        withAnimation {
                            hideXProtectEvents.toggle()
                        }
                    }
                }
                if !hideXProtectEvents {
                    SystemXProtectEventTableView(xprotectEvents: xprotectEvents, eventSelection: $eventSelection, allFilters: $allFilters)
                        .environmentObject(userPrefs)
                }
            }
        }

    }
}

struct SystemEnrichedEventView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager

    @EnvironmentObject var userPrefs: UserPrefs


    @Binding var allFilters: Filters

    var selectedMessage: ESMessage
    var correlatedEvents: [Message]
    @State private var hideUnifiedEnrichments: Bool = false
    
    private var event: ESProcessExecEvent {
        selectedMessage.event.exec!
    }
    
    var body: some View {
        Form {
            VStack(alignment: .leading) {
                Section {
                    HStack {
                        Text("**Unified correlated events (\(correlatedEvents.count))**")
                        Spacer()
                        Button(hideUnifiedEnrichments ? "Show" : "Hide") {
                            withAnimation {
                                hideUnifiedEnrichments.toggle()
                            }
                        }
                    }
                    GroupBox {
                        VStack(alignment: .leading) {
                            HStack {
                                Image(systemName: "info.square")
                                Text("All events we've successfully **correlated to `\(event.target.executable?.name ?? "")`** will show in this unified table. Additionally, and if the events exist we've partitioned out some high value events.")
                            }.frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    
                    // Event correlation table
                    if !hideUnifiedEnrichments {
                        if #available(macOS 14, *) {
                            CustomizableSystemEnrichedTableView(
                                eventsInScope: correlatedEvents,
                                allFilters: $allFilters
                            )
                            .environmentObject(systemExtensionManager)
                            .environmentObject(userPrefs)
                        } else {
                            SystemEnrichedTableView(
                                eventsInScope: correlatedEvents,
                                allFilters: $allFilters
                            )
                            .environmentObject(systemExtensionManager)
                            .environmentObject(userPrefs)
                        }
                    }
                }
                
                SystemRCCorrelatedEventsView(
                    correlatedEvents: correlatedEvents,
                     allFilters: $allFilters
                )
                .environmentObject(systemExtensionManager)
                .environmentObject(userPrefs)
            }.padding([.top, .leading, .trailing])
        }.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        
    }
}
