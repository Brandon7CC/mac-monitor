//
//  SystemGetTaskMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/4/23.
//

import SwiftUI
import SutroESFramework

/// What a `get_task` event says: the kind of task port asked for, and the process whose port it is.
struct SystemGetTaskMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.get_task {
            EventFactsCard(message: esSystemEvent, targetAuditToken: event.target.audit_token_string) {
                FactsBox {
                    FactRow(name: "Type", value: "\(event.type_string) (\(event.type))", style: .monospaced)
                    ProcessView(message: esSystemEvent, process: event.target, ageText: event.target.processAgeText)
                }
            }
        }
    }
}
