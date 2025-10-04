//
//  SystemOpenSSHLoginMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

struct SystemOpenSSHLoginMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    private var event: ESOpenSSHLoginEvent {
        esSystemEvent.event.openssh_login!
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            OpenSSHLoginEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Label("Username:", systemImage: "person.fill")
                            .bold()
                        GroupBox {
                            Text(event.username)
                                .monospaced()
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} Success:")
                            .bold()
                        GroupBox {
                            Text("\(event.success ? "Yes" : "No")")
                                .monospaced()
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} Result type:")
                            .bold()
                        GroupBox {
                            Text("\(event.result_type_string) (\(event.result_type))")
                                .monospaced()
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} Source Address:")
                            .bold()
                        VStack(alignment: .leading) {
                            GroupBox {
                                Text("\(event.source_address_type_string) (\(event.source_address_type))")
                                    .monospaced()
                            }
                            
                            GroupBox {
                                Text(event.source_address)
                                    .monospaced()
                            }
                        }
                        
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            
            Divider()
            
            Label("**Context items**", systemImage: "folder.badge.plus")
                .font(.title2)
                .padding([.leading], 5.0)
            GroupBox {
                HStack {
                    Button("**Audit tokens**") {
                        showAuditTokens.toggle()
                    }
                }.frame(maxWidth: .infinity, alignment: .center).padding(.all)
            }
        }.sheet(isPresented: $showAuditTokens) {
            AuditTokenView(
                audit_token: esSystemEvent.process.audit_token_string,
                responsible_audit_token: esSystemEvent.process.responsible_audit_token_string,
                parent_audit_token: esSystemEvent.process.parent_audit_token_string
            )
            Button("**Dismiss**") {
                showAuditTokens.toggle()
            }.padding(.bottom)
        }
    }
}
