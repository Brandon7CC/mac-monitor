//
//  SystemRemoteThreadCreateMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/4/23.
//

import SwiftUI
import SutroESFramework

/// What a `remote_thread_create` event says: the new thread's state, and the process it was created in.
struct SystemRemoteThreadCreateMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.remote_thread_create {
            EventFactsCard(message: esSystemEvent, targetAuditToken: event.target.audit_token_string) {
                FactsBox {
                    ThreadStateFactsView(state: event.thread_state, flavorName: event.thread_state_string)
                    TargetProcessFacts(process: event.target, style: .monospaced)
                }
            }
        }
    }
}
