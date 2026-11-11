//
//  SystemPTYGrantMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/29/25.
//

import SwiftUI
import SutroESFramework


/// What a `pty_grant` event says: the pseudoterminal's device.
struct SystemPTYGrantMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.pty_grant {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    HStack {
                        Text("\u{2022} **Dev:**")
                        GroupBox {
                            Text("\(String(event.dev))")
                        }
                    }
                }
            }
        }
    }
}
