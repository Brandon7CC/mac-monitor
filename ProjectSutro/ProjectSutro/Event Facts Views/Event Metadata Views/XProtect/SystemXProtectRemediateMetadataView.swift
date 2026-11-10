//
//  SystemXProtectRemediateMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework


/// What an `xp_malware_remediated` event says: the malware XProtect remediated, how and where, whether it worked, and
/// the XProtect version that did it.
struct SystemXProtectRemediateMetadataView: View {
    var esSystemEvent: ESMessage
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.xp_malware_remediated {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    FactRow(name: "Malware Identifier", value: event.malware_identifier)
                    FactRow(name: "Incident ID", value: event.incident_identifier)
                    FactRow(name: "Action type", value: event.action_type)
                    
                    HStack {
                        Text("\u{2022} **Was successful?**")
                        GroupBox {
                            Text("`\(event.success ? "Yes" : "No")`")
                        }
                    }
                    
                    FactRow(name: "Description", value: event.result_description)
                    FactRow(name: "Remediated path", value: event.remediated_path ?? "")
                    FactRow(name: "XProtect version", value: event.signature_version)
                }
            }
        }
    }
}
