//
//  SystemOpenSSHLogoutMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

/// What an `openssh_logout` event says: the user who logged out, and where they had logged in from.
struct SystemOpenSSHLogoutMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.openssh_logout {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    FactRow { Fact("Username", event.username, systemImage: "person.fill") }

                    FactRow {
                        Fact("Source Address", "\(event.source_address_type_string) (\(event.source_address_type))")
                        FactValue(event.source_address)
                    }
                }
            }
        }
    }
}
