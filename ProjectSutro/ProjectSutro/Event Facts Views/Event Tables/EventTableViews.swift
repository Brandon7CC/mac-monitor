//
//  EventTableViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/6/23.
//

import SwiftUI
import SutroESFramework

struct XattrTableView: View {
    @Environment(\.openWindow) private var openEventJSON
    var xattrEvents: [ESMessage]
    @Binding var eventSelection: Set<ESMessage.ID>

    var body: some View {
        Table(xattrEvents, selection: $eventSelection) {
            TableColumn("Process name") { (message: ESMessage) in
                Text(message.process.executable!.name)
            }

            TableColumn("File path") { (message: ESMessage) in
                Text(message.event.deleteextattr!.target.path)
            }

            TableColumn("xattr") { (message: ESMessage) in
                Text(message.event.deleteextattr!.extattr)
            }
        }
        .contextMenu(forSelectionType: ESMessage.ID.self) { selection in
            if !selection.isEmpty {
                Button("View event metadata") {
                    if let selectedID = selection.first {
                        openEventJSON(value: selectedID)
                    }
                }
            }
        }
    }
}


struct LaunchItemTableView: View {
    @Environment(\.openWindow) private var openEventJSON
    var launchItemEvents: [ESMessage]
    @Binding var eventSelection: Set<ESMessage.ID>
    
    var body: some View {
        Section(header: Label("Background Task Management Items", systemImage: "lock.doc").font(.title2)) {
            Table(
of: ESMessage.self,
 selection: $eventSelection,
                  columns: {
                      TableColumn("Process signing ID") { (message: ESMessage) in
                          Text(message.process.signing_id ?? "—")
                      }
                      TableColumn("Launch item path") { (message: ESMessage) in
                          Text(
                            message.event.btm_launch_item_add?.item.item_path ?? "—"
                          )
                      }
                      TableColumn("Persistence type") { (message: ESMessage) in
                          Text(
                            message.event.btm_launch_item_add?.item.item_type_string ?? "—"
                          )
                      }
                  },
                  rows: {
                      ForEach(launchItemEvents) { (message: ESMessage) in
                          TableRow(message).contextMenu {
                              Button("View event metadata") {
                                  openEventJSON(value: message.id)
                              }
                          }
                      }
                  })
        }
    }
}



struct MemoryMapTableView: View {
    @Environment(\.openWindow) private var openEventJSON
    var mmapEvents: [ESMessage]
    @Binding var eventSelection: Set<ESMessage.ID>

    var body: some View {
        Table(mmapEvents, selection: $eventSelection) {
            TableColumn("Process signing ID") { message in
                Text(message.process.signing_id ?? "—")
            }
            .width(min: 80, ideal: 150, max: 250)

            TableColumn("Mapping path") { (message: ESMessage) in
                let path = message.event.mmap?.source.path ?? "—"
                Text("`\(path)`")
                    .background(
                        path.contains("AppleScript.component") ||
                        path.contains("JavaScript.component") ||
                        path.contains(".osax")
                        ? Color.orange.opacity(0.3)
                        : Color.clear
                    )
                    .lineLimit(3)
            }
            .width(min: 150, ideal: 500, max: 2000)
        }
        .contextMenu(forSelectionType: ESMessage.ID.self) { selection in
            Button("View event metadata") {
                if let id = selection.first {
                    openEventJSON(value: id)
                }
            }
        }
    }
}

struct FileTableView: View {
    @Environment(\.openWindow) private var openEventJSON
    var fileEvents: [ESMessage]
    @Binding var eventSelection: Set<ESMessage.ID>

    var body: some View {
        Table(fileEvents, selection: $eventSelection) {
            TableColumn("Process name") { (message: ESMessage) in
                Text(message.process.executable?.name ?? "—")
            }
            .width(min: 80, ideal: 100, max: 200)

            TableColumn("Destination path") { (message: ESMessage) in
                let path: String = {
                    guard let create = message.event.create else { return "—" }
                    switch create.destination {
                    case .new_path(let np): return "\(np.dir.path)/\(np.filename)"
                    case .existing_file(let f): return f.path
                    }
                }()
                Text(path)
            }

            TableColumn("File name") { (message: ESMessage) in
                let name: String = {
                    guard let create = message.event.create else { return "—" }
                    switch create.destination {
                    case .new_path(let np): return np.filename
                    case .existing_file(let f): return URL(fileURLWithPath: f.path).lastPathComponent
                    }
                }()
                Text(name)
            }
            .width(min: 80, ideal: 100, max: 200)
        }
        .contextMenu(forSelectionType: ESMessage.ID.self) { selection in
            Button("View event metadata") {
                if let id = selection.first {
                    openEventJSON(value: id)
                }
            }
        }
    }
}

struct ProcessForkTableView: View {
    @Environment(\.openWindow) private var openEventJSON
    var forkEvents: [ESMessage]
    @Binding var eventSelection: Set<ESMessage.ID>

    var body: some View {
        Table(forkEvents, selection: $eventSelection) {
            TableColumn("Process name") { (message: ESMessage) in
                Text(message.event.fork?.child.executable?.name ?? "—")
            }

            TableColumn("Signing ID") { (message: ESMessage) in
                Text(message.event.fork?.child.signing_id ?? "—")
            }

            TableColumn("Process path") { (message: ESMessage) in
                Text(message.event.fork?.child.executable?.path ?? "—")
            }
        }
        .contextMenu(forSelectionType: ESMessage.ID.self) { selection in
            Button("View event metadata") {
                if let id = selection.first {
                    openEventJSON(value: id)
                }
            }
        }
    }
}




struct ProcessExecTableView: View {
    @Environment(\.openWindow) private var openEventJSON
    var execEvents: [ESMessage]
    @Binding var eventSelection: Set<ESMessage.ID>

    var body: some View {
        Table(execEvents, selection: $eventSelection) {
            TableColumn("Process name") { (message: ESMessage) in
                if let exec = message.event.exec {
                    if exec.target.is_adhoc_signed {
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .symbolRenderingMode(.palette)
                                .foregroundStyle(.black, .yellow)
                            Label("**\(exec.target.executable?.name ?? "—")**", systemImage: "xmark.seal")
                                .symbolRenderingMode(.palette)
                                .foregroundStyle(.red)
                        }
                    } else {
                        Label(exec.target.executable?.name ?? "—", systemImage: "checkmark.seal")
                    }
                } else {
                    Text("—")
                }
            }
            .width(min: 80, ideal: 100, max: 200)

            TableColumn("Signing ID") { (message: ESMessage) in
                Text(message.event.exec?.target.signing_id ?? "—")
            }
            .width(min: 80, ideal: 100, max: 200)

            TableColumn("Process path") { (message: ESMessage) in
                Text("`\(message.event.exec?.target.executable?.path ?? "—")`")
            }
            .width(min: 50, ideal: 60, max: 300)

            TableColumn("Command line") { (message: ESMessage) in
                Text("`\(message.event.exec?.command_line ?? "—")`").lineLimit(5)
            }
            .width(min: 200, ideal: 600, max: .infinity)

            TableColumn("Dangerous entitlements") { (message: ESMessage) in
                DangerousEntitlementView(message: message)
            }
            .width(min: 100, ideal: 150, max: 200)
        }
        .contextMenu(forSelectionType: ESMessage.ID.self) { selection in
            Button("View event metadata") {
                if let id = selection.first {
                    openEventJSON(value: id)
                }
            }
        }
    }
}

