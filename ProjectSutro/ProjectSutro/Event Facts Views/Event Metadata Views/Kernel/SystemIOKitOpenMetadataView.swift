//
//  SystemIOKitOpenMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/4/23.
//

import SwiftUI
import SutroESFramework

/// What an `iokit_open` event says: the user client opened, and the service and driver behind it.
struct SystemIOKitOpenMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.iokit_open {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    FactRow(name: "Client type", value: "\(event.user_client_type)")

                    HStack {
                        Text("\u{2022} **Client class:**")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(event.user_client_class)`")
                                .frame(alignment: .leading)
                        }
                        /// What opening it gives, for a class ``IOKitUserClients`` knows.
                        if let description = event.userClientDescription {
                            InfoTip(text: description)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)

                    /// The service's class, read from the registry at capture, else its path's last component.
                    if let service = event.serviceName {
                        FactRow(name: "Service", value: service, style: .monospaced)
                    }

                    if let driver = event.driver_bundle_id {
                        FactRow(name: "Driver", value: driver, style: .monospaced)
                    }

                    if let parent_path = event.parent_path {
                        FactRow(name: "Parent path", value: parent_path, style: .monospaced)
                    }

                    /// Whenever the record has one, also beside a NULL parent path.
                    if let parentRegistryID = event.parentRegistryID {
                        FactRow(name: "Parent registry ID", value: String(parentRegistryID), style: .monospaced)
                    }
                }
            }
        }
    }
}

