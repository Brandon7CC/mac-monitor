//
//  SystemProcessSocketMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/4/23.
//

import SwiftUI
import SutroESFramework

/// What a `proc_suspend_resume` event says: whether the process was suspended or resumed, and which process it was.
struct SystemProcessSocketMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.proc_suspend_resume {
            EventFactsCard(message: esSystemEvent, targetAuditToken: event.target?.audit_token_string ?? "") {
                FactsBox {
                    FactRow(name: "Suspend / resume type", value: "\(event.type_string) (\(event.type))")
                    TargetProcessFacts(process: event.target, pathName: "Process path")
                }
            }
        }
    }
}
