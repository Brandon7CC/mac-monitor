//
//  SystemAuthorizationJudementMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/28/23.
//

import SwiftUI
import SutroESFramework


/// What an `authorization_judgement` event says: the processes behind the petition, and each right's result.
struct SystemAuthorizationJudgementMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.authorization_judgement {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    AuthorizationProcessesView(instigator: event.instigator, petitioner: event.petitioner)

                    Text("**Results from authorization petition:**")
                    GroupBox {
                        FactsGrid(event.results, columns:
                            .init("Right name") { $0.right_name },
                            .init("Rule class") { $0.ruleClassShortName },
                            .init("Granted") { $0.granted ? "Yes" : "No" })
                    }
                }
            }
        }
    }
}
