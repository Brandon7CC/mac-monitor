//
//  SystemProfileAddMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/6/23.
//

import SwiftUI
import SutroESFramework

/// What a `profile_add` event says: the configuration profile installed, where it came from, and whether it was an
/// update.
struct SystemProfileAddMetadataView: View {
    var esSystemEvent: ESMessage
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.profile_add {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    if let profile = event.profile {
                        FactRow(name: "Profile display name", value: profile.display_name, stacked: true,
                                style: .monospaced)
                        FactRow(name: "Profile identifer", value: profile.identifier, stacked: true,
                                style: .monospaced)
                        FactRow(name: "Organization", value: profile.organization, stacked: true, style: .monospaced)
                        
                        HStack {
                            Text("\u{2022} Source type:")
                                .bold()
                                .padding([.leading], 5.0)
                            GroupBox {
                                Text("\(profile.installSourceShortName) (\(profile.install_source))")
                                    .monospaced()
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            Text("\u{2022} Is update:")
                                .bold()
                                .padding([.leading], 5.0)
                            GroupBox {
                                Text("\(event.is_update ? "Yes" : "No")")
                                    .monospaced()
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
        }
    }
}
