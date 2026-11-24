//
//  SystemOpenSSHLoginMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

/// What an `openssh_login` event says: the user, whether and how the login succeeded, and where it came from.
struct SystemOpenSSHLoginMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.openssh_login {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    FactRow { Fact("Username", event.username, systemImage: "person.fill") }

                    FactRow(name: "Success", value: event.success ? "Yes" : "No")
                    FactRow(name: "Result type", value: "\(event.result_type_string) (\(event.result_type))")

                    FactRow {
                        Fact("Source Address", "\(event.source_address_type_string) (\(event.source_address_type))")
                        FactValue(event.source_address)
                    }
                }
            }
        }
    }
}
