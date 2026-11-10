//
//  SystemProcessCheckMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/4/23.
//

import SwiftUI
import SutroESFramework

/// What a `proc_check` event says: the check's type and flavor, and the process it checked.
struct SystemProcessCheckMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.proc_check {
            EventFactsCard(message: esSystemEvent,
                           targetAuditToken: event.target?.audit_token_string ?? "Unknown") {
                FactsBox {
                    FactRow(name: "Type / flavor", value: "\(event.type_string) (\(event.type)) / (\(event.flavor))")
                    TargetProcessFacts(process: event.target)
                }
            }
        }
    }
}
