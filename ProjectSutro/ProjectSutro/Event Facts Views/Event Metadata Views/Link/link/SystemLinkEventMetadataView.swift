//
//  SystemLinkEventMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/3/23.
//

import SwiftUI
import SutroESFramework

/// What a `link` event says: the file linked, and the new link to it.
struct SystemLinkEventMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.link {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    if let srcPath = event.source.path {
                        FactRow(name: "Source file path", value: srcPath, stacked: true)
                    }
                    if let tgtPath = esSystemEvent.target_path {
                        FactRow(name: "Destination file path", value: tgtPath, stacked: true)
                    }

                    Divider()

                    FactRow {
                        Fact("Source file name", event.source.name)
                        Image(systemName: "arrow.right")
                        Fact("Destination file name", event.target_filename)
                    }
                }
            }
        }
    }
}
