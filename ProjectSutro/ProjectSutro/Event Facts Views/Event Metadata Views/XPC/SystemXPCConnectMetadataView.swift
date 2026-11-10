//
//  SystemXPCConnectMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/26/23.
//

import SwiftUI
import SutroESFramework


/// What an `xpc_connect` event says: the XPC service connected to, and its domain.
struct SystemXPCConnectMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.xpc_connect {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    FactRow(name: "Service name", value: event.service_name, style: .monospaced)
                    FactRow(name: "Domain type", value: event.service_domain_type_string, style: .monospaced)
                }
            }
        }
    }
}
