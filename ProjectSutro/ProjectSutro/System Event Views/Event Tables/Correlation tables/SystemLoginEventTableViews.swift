//
//  SystemLoginEventTableViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 2/24/23.
//

import SwiftUI
import SutroESFramework


struct SystemLoginEventTableView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.openWindow) private var openEventJSON
    
    @EnvironmentObject var userPrefs: UserPrefs
    
    var loginEvents: [ESMessage]
    @Binding var eventSelection: Set<ESMessage.ID>
    
    @Binding var allFilters: Filters
    
    
    var body: some View {
        Section(header: Label("Login events", systemImage: "ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN").font(.title2)) {
            Table(of: ESMessage.self, selection: $eventSelection) {
                TableColumn("Type", value: \.es_event_type)
                TableColumn("Target") { Text($0.context ?? "") }
            } rows: {
                ForEach(loginEvents) { (message: ESMessage) in
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
}
