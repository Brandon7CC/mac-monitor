//
//  SystemMProtectMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/14/25.
//

import SwiftUI
import SutroESFramework

/// What an `mprotect` event says: the protection asked for, the memory it's for, and its flags.
struct SystemMProtectMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.mprotect {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    FactRow {
                        Fact("Protection", "\(event.protection)")
                        Fact("Address", event.hex_address)
                        Fact("Size", "\(event.kb_size) kb")
                    }

                    // MARK: Protection flags
                    if !event.flags.isEmpty {
                        GroupBox {
                            VStack(alignment: .leading) {
                                Label("**VM Protection Flags**", systemImage: "doc.plaintext")
                                    .padding(.bottom, 5)
                                    .font(.title3)

                                ForEach(event.flags, id: \.self) { flag in
                                    GroupBox {
                                        Text("\u{2022} \(flag)")
                                            .monospaced()
                                    }
                                }
                            }.frame(maxWidth: .infinity, alignment: .topLeading)
                        }
                    }
                }
            }
        }
    }
}
