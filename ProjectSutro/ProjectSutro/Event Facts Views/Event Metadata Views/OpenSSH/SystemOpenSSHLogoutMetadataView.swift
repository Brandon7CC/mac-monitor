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
                    HStack {
                        Label("Username:", systemImage: "person.fill")
                            .bold()
                        GroupBox {
                            Text(event.username)
                                .monospaced()
                        }
                    }

                    HStack {
                        Text("\u{2022} Source Address:")
                            .bold()
                        VStack(alignment: .leading) {
                            GroupBox {
                                Text("\(event.source_address_type_string) (\(event.source_address_type))")
                                    .monospaced()
                            }

                            GroupBox {
                                Text(event.source_address)
                                    .monospaced()
                            }
                        }
                    }
                }
            }
        }
    }
}
