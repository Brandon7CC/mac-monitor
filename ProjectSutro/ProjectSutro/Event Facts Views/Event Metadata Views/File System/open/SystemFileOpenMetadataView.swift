//
//  SystemFileOpenMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/3/23.
//

import SwiftUI
import SutroESFramework

/// What an `open` event says: the file opened.
struct SystemFileOpenMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.open {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    FactRow(name: "File name", value: event.file.name)
                    FactRow(name: "File path", value: event.file.path ?? "", stacked: true)
                }
            }
        }
    }
}
