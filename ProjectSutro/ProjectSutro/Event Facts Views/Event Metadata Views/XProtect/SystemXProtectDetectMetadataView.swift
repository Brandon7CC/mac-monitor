//
//  SystemXProtectDetectMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

/// What an `xp_malware_detected` event says: the malware XProtect found, where, and the XProtect version that found
/// it.
struct SystemXProtectDetectMetadataView: View {
    var esSystemEvent: ESMessage
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.xp_malware_detected {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    FactRow(name: "Malware Identifier", value: event.malware_identifier)
                    FactRow(name: "Incident ID", value: event.incident_identifier)
                    FactRow(name: "Detected path", value: event.detected_path)
                    if let executable = event.detected_executable {
                        FactRow(name: "Executable path", value: executable, style: .monospaced)
                    }
                    FactRow(name: "XProtect version", value: event.signature_version)
                }
            }
        }
    }
}
