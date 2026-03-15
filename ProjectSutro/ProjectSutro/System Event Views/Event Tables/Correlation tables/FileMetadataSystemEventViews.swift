//
//  FileMetadataSystemEventViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/16/22.
//

import SwiftUI
import SutroESFramework


struct SystemXattrTableView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.openWindow) private var openEventJSON
    @EnvironmentObject var userPrefs: UserPrefs
    
    var xattrEvents: [ESMessage]
    @Binding var eventSelection: Set<ESMessage.ID>
    @Binding var allFilters: Filters
    
    var body: some View {
        Table(of: ESMessage.self, selection: $eventSelection) {
            TableColumn("xattr") { message in
                Text(message.event.deleteextattr!.extattr)
            }
            TableColumn("File path") { message in
                Text(message.event.deleteextattr!.target.path)
            }
        } rows: {
            ForEach(xattrEvents) { message in
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


struct SystemFileMetadataEventTableViews: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.openWindow) private var openEventJSON
    
    @EnvironmentObject var userPrefs: UserPrefs
    
    var eventsInScope: [ESMessage]
    @Binding var eventSelection: Set<ESMessage.ID>
    @Binding var allFilters: Filters
    
    var body: some View {
        Divider()
        Section(header: Label("File metadata", systemImage: "filemenu.and.selection").font(.title2)) {
            VStack(alignment: .leading) {
                Text("**Extended attribute deletion**")
                SystemXattrTableView(
                    xattrEvents: eventsInScope
                        .filter {
                            $0.event.deleteextattr?.extattr != nil
                        },
                    eventSelection: $eventSelection,
                    allFilters: $allFilters)
                    .environmentObject(userPrefs)
            }.frame(alignment: .leading)
        }.frame(alignment: .leading)
    }
}
