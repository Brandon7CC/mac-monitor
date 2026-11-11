//
//  SystemFileWriteMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/3/23.
//

import SwiftUI
import SutroESFramework

/// What a `write` event says: the file written.
struct SystemFileWriteMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.write {
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
