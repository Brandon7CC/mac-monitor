//
//  SystemUIPCConnectMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/1/25.
//


import SwiftUI
import SutroESFramework


struct SystemUIPCConnectMetadataView: View {
    var message: ESMessage
    @State private var showAuditTokens: Bool = false
    
    private var event: ESUIPCConnectEvent {
        message.event.uipc_connect!
    }
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if message.event.uipc_connect != nil {
            eventContent
        }
    }

    @ViewBuilder
    private var eventContent: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            SystemEventTypeLabel(message: message)
                .font(.title2)
                
            
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Text("\u{2022} Type:")
                            .bold()
                        GroupBox {
                            Text("\(event.type_string) (\(event.type))")
                                .monospaced()
                        }
                        
                        Text("\u{2022} Protocol:")
                            .bold()
                        GroupBox {
                            Text("\(event.protocol_string) (\(event.protocol))")
                                .monospaced()
                        }
                        
                        Text("\u{2022} Domain:")
                            .bold()
                        GroupBox {
                            Text("\(event.domain_string) (\(event.domain))")
                                .monospaced()
                        }
                    }
                    
                    if let path = event.file.path {
                        HStack {
                            Text("\u{2022} File path:")
                                .bold()
                            GroupBox {
                                Text(path)
                                    .monospaced()
                            }
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
