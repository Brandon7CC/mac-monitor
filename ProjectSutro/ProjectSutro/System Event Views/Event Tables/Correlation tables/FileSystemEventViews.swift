//
//  FileSystemEventViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/17/22.
//

import SwiftUI
import SutroESFramework


struct SystemFileEventTableView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @Environment(\.openWindow) private var openEventJSON
    
    @EnvironmentObject var userPrefs: UserPrefs
    
    var fileEvents: [ESMessage]
    @Binding var eventSelection: Set<ESMessage.ID>
    
    @Binding var allFilters: Filters
    
    
    var body: some View {
        Section(header: Label("File creations", systemImage: "note.text.badge.plus").font(.title2)) {
            Table(of: ESMessage.self, selection: $eventSelection) {
                TableColumn("File name") { message in
                    if let create = message.event.create {
                        HStack {
                            if create.is_quarantined == 0 {
                                Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.black, .orange).help("This file is potentially not quarantined (generally, this is not a problem on its own)")
                            }
                            Text(create.fileName)
                        }
                    }
                    
                }.width(min: 100, ideal: 150, max: 400)
                TableColumn(
                    "File path",
                    value: \.sortCreateTarget
                )
                TableColumn("Is quarantined") { message in
                    if let create = message.event.create {
                        HStack {
                            if create.is_quarantined == 0 {
                                Text("Not quarantined")
                            } else if create.is_quarantined == 1 {
                                Text("Quarantined")
                            } else {
                                Text("Does not exist")
                            }
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
