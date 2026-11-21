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
                        FactRow(name: "Profile display name", value: profile.display_name)
                        FactRow(name: "Profile identifer", value: profile.identifier)
                        FactRow(name: "Organization", value: profile.organization)
                        
                        FactRow {
                            Fact("Source type", "\(profile.installSourceShortName) (\(profile.install_source))")
                            Fact("Is update", event.is_update ? "Yes" : "No")
                        }
                    }
                }
            }
        }
    }
}
