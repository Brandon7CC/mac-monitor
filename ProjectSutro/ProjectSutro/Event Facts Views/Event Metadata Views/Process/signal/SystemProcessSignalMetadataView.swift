//
//  SystemProcessSignalMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/4/23.
//

import SwiftUI
import SutroESFramework

/// What a `signal` event says: the signal, and the process it was sent to.
struct SystemProcessSignalMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.signal {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    FactRow(name: "Signal", value: "\(event.signal_name) (\(event.sig))")
                    TargetProcessFacts(process: event.target)
                }
            }
        }
    }
}
