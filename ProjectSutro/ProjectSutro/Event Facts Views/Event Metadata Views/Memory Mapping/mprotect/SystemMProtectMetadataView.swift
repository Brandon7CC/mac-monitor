//
//  SystemMProtectMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/14/25.
//

import SwiftUI
import SutroESFramework

struct SystemMProtectMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    private var event: ESMProtectEvent {
        esSystemEvent.event.mprotect!
    }
    
    private var protection: Int32 {
        event.protection
    }
    
    private var address: Int64 {
        event.address
    }
    
    private var size: Int64 {
        event.size
    }
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if esSystemEvent.event.mprotect != nil {
            eventContent
        }
    }

    @ViewBuilder
    private var eventContent: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            SystemEventTypeLabel(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Text("\u{2022} **Protection:**")
                        GroupBox {
                            Text("`\(protection)`")
                        }
                        
                        Text("\u{2022} **Address:**")
                        GroupBox {
                            Text(event.hex_address)
                                .monospaced()
                        }
                        
                        Text("\u{2022} **Size:**")
                        GroupBox {
                            Text("\(event.kb_size) kb")
                                .monospaced()
                        }
                    }
                    
                    // MARK: Protection flags
                    if !event.flags.isEmpty {
                        GroupBox {
                            VStack(alignment: .leading) {
                                Label("**VM Protection Flags**", systemImage: "doc.plaintext")
                                    .padding(.bottom, 5)
                                    .font(.title3)
                                
                                ForEach(event.flags, id: \.self) { flag in
                                    GroupBox {
                                        Text("\u{2022} \(flag)")
                                            .monospaced()
                                    }
                                }
                            }.frame(maxWidth: .infinity, alignment: .topLeading)
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

