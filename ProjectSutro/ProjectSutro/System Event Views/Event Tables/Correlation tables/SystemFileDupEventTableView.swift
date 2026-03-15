//
//  SystemFileDupEventTableView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 2/24/23.
//

import SwiftUI
import SutroESFramework


struct SystemFileDupEventTableView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.openWindow) private var openEventJSON
    
    @EnvironmentObject var userPrefs: UserPrefs
    
    var fileEvents: [ESMessage]
    @Binding var eventSelection: Set<ESMessage.ID>
    
    @Binding var allFilters: Filters
    
    
    var body: some View {
        Section(header: Label("FD duplication", systemImage: eventStringToImage(from: "ES_EVENT_TYPE_NOTIFY_DUP")).font(.title2)) {
            Table(of: ESMessage.self, selection: $eventSelection) {
                TableColumn("File path", value: \.event.dup!.target.path)
            } rows: {
                ForEach(fileEvents) { message in
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
