//
//  SystemIOKitOpenEvent.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/4/23.
//

import SwiftUI
import SutroESFramework

struct SystemIOKitOpenMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    @State private var showTargetAuditTokens: Bool = false
    
    private var event: ESIOKitOpenEvent {
        esSystemEvent.event.iokit_open!
    }
    
    private var eventType: String {
        esSystemEvent.es_event_type
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            IOKitOpenEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Text("\u{2022} **Client type:**")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(event.user_client_type)`")
                                .frame(alignment: .leading)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    HStack{
                        Text("\u{2022} **Client class:**")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(event.user_client_class)`")
                                .frame(alignment: .leading)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    if let parent_path = event.parent_path {
                        HStack{
                            Text("\u{2022} **Parent path:**")
                                .padding([.leading], 5.0)
                            GroupBox {
                                Text(parent_path)
                                    .monospaced()
                                    .frame(alignment: .leading)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                        
                        HStack{
                            Text("\u{2022} **Parent registry ID:**")
                                .padding([.leading], 5.0)
                            GroupBox {
                                Text("\(String(event.parent_registry_id))")
                                    .monospaced()
                                    .frame(alignment: .leading)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
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
            }.buttonStyle(.borderedProminent).tint(.pink).opacity(0.8).padding(.trailing).padding(.bottom)
        }
    }
}

