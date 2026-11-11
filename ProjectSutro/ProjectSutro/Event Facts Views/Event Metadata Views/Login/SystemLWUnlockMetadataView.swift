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
                    HStack {
                        Label("**Username:**", systemImage: "person.fill")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(event.username ?? "Unknown")`")
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)

                    FactRow(name: "Graphical session ID", value: "\(UInt32(bitPattern: event.graphical_session_id))")
                }
            }
        }
    }
}
