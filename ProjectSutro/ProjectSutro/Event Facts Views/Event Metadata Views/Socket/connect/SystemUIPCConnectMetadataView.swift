//
//  SystemUIPCConnectMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/1/25.
//


import SwiftUI
import SutroESFramework


/// What a `uipc_connect` event says: the socket's type, protocol and domain, and the socket file connected to.
struct SystemUIPCConnectMetadataView: View {
    var message: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = message.event.uipc_connect {
            EventFactsCard(message: message) {
                FactsBox {
                    FactRow {
                        Fact("Type", "\(event.type_string) (\(event.type))")
                        Fact("Protocol", "\(event.protocol_string) (\(event.protocol))")
                        Fact("Domain", "\(event.domain_string) (\(event.domain))")
                    }

                    if let path = event.file.path {
                        FactRow(name: "File path", value: path)
                    }
                }
            }
        }
    }
}
