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
                    HStack {
                        Label("**Username:**", systemImage: "person.fill")
                            .padding([.leading], 5.0)
                        GroupBox {
                            let username = event.username ?? "Unknown"
                            if let uid = event.uid {
                                Text("`\(username) (\(uid))`")
                            } else {
                                Text("`\(username)`")
                            }
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)

                    FactRow(name: "Success", value: event.success ? "Yes" : "No")
                    if let failureMessage = event.failure_message, !failureMessage.isEmpty {
                        FactRow(name: "Failure message", value: failureMessage)
                    }
                }
            }
        }
    }
}
