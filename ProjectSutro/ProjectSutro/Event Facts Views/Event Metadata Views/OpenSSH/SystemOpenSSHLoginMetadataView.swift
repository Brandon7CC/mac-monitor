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
                    HStack {
                        Label("Username:", systemImage: "person.fill")
                            .bold()
                        GroupBox {
                            Text(event.username)
                                .monospaced()
                        }
                    }

                    FactRow(name: "Success", value: event.success ? "Yes" : "No", style: .monospaced)
                    FactRow(name: "Result type", value: "\(event.result_type_string) (\(event.result_type))",
                            style: .monospaced)

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
