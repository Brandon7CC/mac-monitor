//
//  SystemFileRenameEventTableView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 2/24/23.
//

import SwiftUI
import SutroESFramework


struct SystemFileRenameEventTableView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.openWindow) private var openEventJSON
    
    @EnvironmentObject var userPrefs: UserPrefs
    
    var fileEvents: [ESMessage]
    @Binding var eventSelection: Set<ESMessage.ID>
    
    @Binding var allFilters: Filters
    
    var body: some View {
        Section(header: Label("File renames", systemImage: eventStringToImage(from: "ES_EVENT_TYPE_NOTIFY_RENAME")).font(.title2)) {
            Table(of: ESMessage.self, selection: $eventSelection) {
                
                TableColumn("Destination name") { message in
                    if let rename = message.event.rename,
                       let fileName = URL(string: rename.destination_path)?.lastPathComponent {
                        HStack {
                            Text(fileName)
                        }
                    }
                    
                }.width(min: 100, ideal: 150, max: 400)
                
                TableColumn("Destination path", value: \.event.rename!.destination_path)
                
                TableColumn("Source path", value: \.event.rename!.source.path)
                
//                TableColumn("Is quarantined", value: \.file_rename_event!.is_quarantined.description)
                TableColumn("Is quarantined") { message in
                    HStack {
                        if message.event.rename!.is_quarantined == 0 {
                            Text("Not quarantined")
                        } else if message.event.rename!.is_quarantined == 1 {
                            Text("Quarantined")
                        } else {
                            Text("Does not exist")
                        }
                    }
                }
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
