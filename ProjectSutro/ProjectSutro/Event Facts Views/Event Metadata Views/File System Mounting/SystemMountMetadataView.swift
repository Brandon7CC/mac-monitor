//
//  SystemMountMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

/// What a `mount` event says: what was mounted, where, and how.
struct SystemMountMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.mount {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    FactRow(name: "Source path", value: event.statfs.f_mntfromname, style: .monospaced)
                    FactRow(name: "Mount directory", value: event.statfs.f_mntonname, style: .monospaced)
                    HStack {
                        Text("\u{2022} **Type:**")
                        GroupBox {
                            Text(event.disposition_string.droppingPrefix("ES_MOUNT_DISPOSITION_"))
                                .monospaced()
                        }
                        Text("\u{2022} **Total files:**")
                        GroupBox {
                            Text(String(event.statfs.f_files))
                                .monospaced()
                        }
                    }
                }
            }
        }
    }
}

