//
//  SystemFileCreateMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework


struct FileQuarantineStatusLabelView: View {
    var isQuarantined: Int

    var quarantinedColor: Color = Color(cgColor: .init(red: 58/255.0, green: 194/255.0, blue: 72/255.0, alpha: 1.0))
    var notQuarantinedColor: Color = Color(cgColor: .init(red: 242/255.0, green: 100/255.0, blue: 90/255.0, alpha: 1.0))


    var body: some View {
        if isQuarantined != 2 {
            Group {
                HStack {
                    Image(systemName: "lock.shield")
                        .symbolRenderingMode(.palette)
                        .foregroundColor(.black)
                        .font(Font.system(size: 13, weight: .bold))
                    if isQuarantined == 1 {
                        Text("**`Quarantined`**").foregroundColor(.black)
                    } else if isQuarantined == 0 {
                        Text("**`Not quarantined`**").foregroundColor(.black)
                    }
                }.padding(5.0)
            }.background(
                RoundedRectangle(cornerSize: .init(width: 5.0, height: 5.0)).fill(self.isQuarantined == 1 ? quarantinedColor : notQuarantinedColor)
            ).help(self.isQuarantined == 1 ? "This file is quarantined" : "This file is not quarantined")
        }
    }
}

/// What a `create` event says: the file created, whether it's quarantined, and its ACL and mode.
struct SystemFileCreateMetadataView: View {
    var esSystemEvent: ESMessage

    /// Whether the process that made the file is File Quarantine-aware.
    private var fileQuarantineEnabled: Bool {
        esSystemEvent.process.file_quarantine_type != "DISABLED"
    }

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.create {
            let fileQuarantineType = Int(event.is_quarantined)
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    if fileQuarantineEnabled && fileQuarantineType == 0 {
                        GroupBox {
                            HStack {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .symbolRenderingMode(.palette)
                                    .foregroundStyle(.black, .yellow)
                                Text("""
                                    This file is potentially *not* quarantined by a "File Quarantine-aware" \
                                    application. False positives exist (e.g. if the attribute is quickly deleted) and \
                                    the existance of the `com.apple.quarantine` extended attribute should be \
                                    investigated.
                                    """)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }

                    FactRow(name: "Type", value: event.destination_type_string)

                    HStack {
                        Text("\u{2022} **File name:**")
                        GroupBox {
                            Text("`\(event.fileName)`")
                        }
                        FileQuarantineStatusLabelView(isQuarantined: fileQuarantineType)
                    }

                    HStack {
                        FileExistsLabel(title: "**File path:**", path: event.targetPath)
                        GroupBox {
                            Text("`\(event.targetPath)`")
                                .lineLimit(10)
                        }
                        ShowInFinderButton(path: event.targetPath)
                    }

                    if let acl = event.acl {
                        FactRow(name: "ACL", value: acl.trimmingCharacters(in: .whitespacesAndNewlines))
                    }

                    if let mode = event.destination.new_path?.mode {
                        FactRow(name: "Mode", value: "\(mode.int32Value)")
                    }
                }
            }
        }
    }
}
