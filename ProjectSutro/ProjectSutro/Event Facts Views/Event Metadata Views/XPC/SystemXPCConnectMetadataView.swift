//
//  SystemXPCConnectMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/26/23.
//

import SwiftUI
import SutroESFramework


struct SystemXPCConnectMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    private var event: ESXPCConnectEvent {
        esSystemEvent.event.xpc_connect!
    }

    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            IntelligentEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Text("\u{2022} Service name:")
                            .bold()
                        GroupBox {
                            Text(event.service_name)
                                .monospaced()
                        }
                    }

                    HStack {
                        Text("\u{2022} Domain type:")
                        GroupBox {
                            Text(event.service_domain_type_string)
                                .monospaced()
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
