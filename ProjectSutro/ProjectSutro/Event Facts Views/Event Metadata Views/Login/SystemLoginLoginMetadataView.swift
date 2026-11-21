//
//  SystemLoginLoginMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

/// What a `login_login` event says: the user, whether the login succeeded, and why it failed when it did.
struct SystemLoginLoginMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.login_login {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    let username = event.username ?? "Unknown"
                    let user = event.uid.map { "\(username) (\($0))" } ?? username
                    FactRow { Fact("Username", user, systemImage: "person.fill") }

                    FactRow(name: "Success", value: event.success ? "Yes" : "No")
                    if let failureMessage = event.failure_message, !failureMessage.isEmpty {
                        FactRow(name: "Failure message", value: failureMessage)
                    }
                }
            }
        }
    }
}
