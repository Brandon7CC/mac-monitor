//
//  SystemLWUnlockMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/18/23.
//

import SwiftUI
import SutroESFramework

/// What an `lw_session_unlock` event says: the user who unlocked the screen, and the graphical session.
struct SystemLWUnlockMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.lw_session_unlock {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    FactRow { Fact("Username", event.username, systemImage: "person.fill") }

                    FactRow(name: "Graphical session ID", value: "\(UInt32(bitPattern: event.graphical_session_id))")
                }
            }
        }
    }
}
