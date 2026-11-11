//
//  SystemGatekeeperUserOverrideMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 8/22/25.
//

import SwiftUI
import SutroESFramework


/// What a `gatekeeper_user_override` event says: the file the user let past Gatekeeper, its type and hash, and its code
/// signing.
struct SystemGatekeeperUserOverrideMetadataView: View {
    var message: ESMessage
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = message.event.gatekeeper_user_override {
            EventFactsCard(message: message) {
                FactsBox {
                    FactRow(name: "Override path", value: message.target_path ?? "", style: .monospaced)
                    FactRow(name: "File type", value: event.file_type_string, style: .monospaced)
                    FactRow(name: "SHA256", value: event.sha256, style: .monospaced)
                    
                    if let codeSigning = event.signing_info {
                        Divider()
                        
                        FactsBox {
                            Label("Code signing details", systemImage: "signature")
                                .bold()
                                .font(.title3)
                            
                            if let signingID = codeSigning.signing_id.nonEmpty {
                                FactRow(name: "Signing ID", value: signingID, style: .monospaced)
                            }
                            
                            if let teamID = codeSigning.team_id.nonEmpty {
                                FactRow(name: "Team ID", value: teamID, style: .monospaced)
                            }
                            
                            if !codeSigning.cdhash.isEmpty {
                                FactRow(name: "CDHash", value: codeSigning.cdhash, style: .monospaced)
                            }
                        }
                    }
                }
            }
        }
    }
}
