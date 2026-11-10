//
//  SystemUnlinkEventMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/3/23.
//

import SwiftUI
import SutroESFramework

/// What an `unlink` event says: the file deleted.
struct SystemUnlinkEventMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.unlink {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    FactRow(name: "File name", value: event.target.name, style: .monospaced)
                    if let path = event.target.path {
                        FactRow(name: "File path", value: path, stacked: true, style: .monospaced)
                    }
                }
            }
        }
    }
}
