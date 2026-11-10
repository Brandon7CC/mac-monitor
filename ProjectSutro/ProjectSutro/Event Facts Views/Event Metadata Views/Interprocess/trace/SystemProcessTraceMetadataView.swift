//
//  SystemProcessTraceMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/4/23.
//

import SwiftUI
import SutroESFramework

/// What a `trace` event says: the process being traced.
struct SystemProcessTraceMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.trace {
            EventFactsCard(message: esSystemEvent, targetAuditToken: event.target.audit_token_string) {
                FactsBox {
                    TargetProcessFacts(process: event.target)
                }
            }
        }
    }
}
