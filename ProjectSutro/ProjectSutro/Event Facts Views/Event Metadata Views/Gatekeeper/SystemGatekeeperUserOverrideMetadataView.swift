//
//  SystemGatekeeperUserOverrideMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 8/22/25.
//

import SwiftUI
import SutroESFramework


struct SystemGatekeeperUserOverrideMetadataView: View {
    var message: ESMessage
    @State private var showAuditTokens: Bool = false
    @State private var showInstigator: Bool = false
    
    private var event: ESGatekeeperUserOverrideEvent {
        message.event.gatekeeper_user_override!
    }
    
    private var overridePath: String {
        switch event.file {
        case .file_path(let path):
            return path
        case .file(let file):
            return file.path
        }
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            SystemEventTypeLabel(message: message)
                .font(.title2)
                
            
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Text("\u{2022} **Override path:**")
                        GroupBox {
                            Text(overridePath)
                                .monospaced()
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} **File type**")
                        GroupBox {
                            Text(event.file_type_string)
                                .monospaced()
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} **SHA256**")
                        GroupBox {
                            Text(event.sha256 ?? "")
                                .monospaced()
                        }
                    }
                    
                    if let codeSigning = event.signing_info {
                        Divider()
                        
                        GroupBox {
                            VStack(alignment: .leading) {
                                Label("Code signing details", systemImage: "signature")
                                    .bold()
                                    .font(.title3)
                                
                                if !codeSigning.signing_id.isEmpty {
                                    HStack {
                                        Text("\u{2022} **Signing ID**")
                                        GroupBox {
                                            Text(codeSigning.signing_id)
                                                .monospaced()
                                        }
                                    }
                                }
                                
                                if !codeSigning.team_id.isEmpty {
                                    HStack {
                                        Text("\u{2022} **Team ID**")
                                        GroupBox {
                                            Text(codeSigning.team_id)
                                                .monospaced()
                                        }
                                    }
                                }
                                
                                if !codeSigning.cdhash.isEmpty {
                                    HStack {
                                        Text("\u{2022} **CDHash**")
                                        GroupBox {
                                            Text(codeSigning.cdhash)
                                                .monospaced()
                                        }
                                    }
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        
                        
                    }
                    
                    
                }.frame(maxWidth: .infinity, alignment: .leading)
                
                
            }
            
            Divider()
            
            Label("**Context items**", systemImage: "folder.badge.plus").font(.title2).padding([.leading], 5.0)
            GroupBox {
                HStack {
                    Button("**Audit tokens**") {
                        showAuditTokens.toggle()
                    }
                }.frame(maxWidth: .infinity, alignment: .center).padding(.all)
            }
        }.sheet(isPresented: $showAuditTokens) {
            AuditTokenView(
                audit_token: message.process.audit_token_string,
                responsible_audit_token: message.process.responsible_audit_token_string,
                parent_audit_token: message.process.parent_audit_token_string
            )
            Button("**Dismiss**") {
                showAuditTokens.toggle()
            }.padding(.bottom)
        }
    }
}
