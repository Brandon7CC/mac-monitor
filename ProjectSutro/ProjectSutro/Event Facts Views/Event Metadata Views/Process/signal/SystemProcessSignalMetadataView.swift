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
            EventFactsCard(message: esSystemEvent, targetAuditToken: event.target.audit_token_string) {
                FactsBox {
                    FactRow(name: "Signal", value: "\(event.signal_name) (\(event.sig))")
                    FactRow(name: "Target process name", value: event.target.executable?.name)
                    FactRow(name: "Target process path", value: event.target.executable?.path, stacked: true)
                    if let signingID = event.target.signing_id, !signingID.isEmpty {
                        FactRow(name: "Signing ID", value: signingID)
                    }
                }
            }
        }
    }
}
