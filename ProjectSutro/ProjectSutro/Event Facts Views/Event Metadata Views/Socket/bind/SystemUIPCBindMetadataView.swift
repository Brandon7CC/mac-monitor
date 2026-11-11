//
//  SystemUIPCBindMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/1/25.
//

import SwiftUI
import SutroESFramework


/// What a `uipc_bind` event says: the socket file bound, and its mode.
struct SystemUIPCBindMetadataView: View {
    var message: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = message.event.uipc_bind {
            EventFactsCard(message: message) {
                FactsBox {
                    if let path = message.target_path {
                        FactRow(name: "File path", value: path, style: .monospaced)
                    }
                    FactRow(name: "Mode", value: String(event.mode), style: .monospaced)
                }
            }
        }
    }
}
