//
//  SystemFileCloseMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/3/23.
//

import SwiftUI
import SutroESFramework

/// What a `close` event says: the file closed, its type, and whether it was written.
struct SystemFileCloseMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.close {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    FactRow(name: "File name", value: event.target.name, style: .monospaced)

                    /// As create and rename show theirs: whether the file is still there, and Show in Finder while
                    /// it is.
                    if let path = event.target.path {
                        HStack {
                            FileExistsLabel(title: "**File path:**", path: path)
                            GroupBox {
                                Text(path)
                                    .monospaced()
                                    .lineLimit(10)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            ShowInFinderButton(path: path)
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }

                    /// Read from a modified file's first bytes when the event was recorded: none when it wasn't read.
                    if let fileType = event.file_type {
                        FileTypeFact(identifier: fileType, machOType: event.mach_o_type)
                            .padding([.leading], 5.0)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }

                    writeFacts(event)
                }
            }
        }
    }

    /// Whether the file was written through the descriptor, and whether it was mapped writable: Mac Monitor keeps only
    /// modified closes by default, and a file changed only through a writable mapping closes unmodified. Endpoint
    /// Security reports `was_mapped_writable` from message version 6.
    ///
    /// - Parameter event: The close.
    /// - Returns: Both facts on one line.
    private func writeFacts(_ event: ESFileCloseEvent) -> some View {
        HStack {
            Text("\u{2022} **Modified:**")
                .padding([.leading], 5.0)
            GroupBox {
                Text("`\(String(event.modified))`")
            }.help("Whether the file was written through this descriptor before it closed.")

            if esSystemEvent.version >= 6 {
                Text("\u{2022} **Mapped writable:**")
                GroupBox {
                    Text("`\(String(event.was_mapped_writable))`")
                }.help("Whether the file was mapped writable. A file changed only through a writable mapping closes "
                       + "unmodified.")
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}
