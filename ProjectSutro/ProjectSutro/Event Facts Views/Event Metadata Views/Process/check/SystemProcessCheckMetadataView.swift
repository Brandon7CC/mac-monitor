//
//  SystemProcessCheckMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/4/23.
//

import SwiftUI
import SutroESFramework

struct SystemProcessCheckMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    @State private var showTargetAuditTokens: Bool = false
    
    var event: ESProcessCheckEvent {
        esSystemEvent.event.proc_check!
    }
    
    var targetProcName: String {
        event.target?.executable?.name ?? "Unknown"
    }
    
    var targetProcPath: String {
        event.target?.executable?.path ?? "Unknown"
    }
    
    var auditToken: String {
        event.target?.audit_token_string ?? "Unknwon"
    }
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if esSystemEvent.event.proc_check != nil {
            eventContent
        }
    }

    @ViewBuilder
    private var eventContent: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            SystemEventTypeLabel(message: esSystemEvent).font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Text("\u{2022} **Type / flavor:**")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(event.type_string) (\(event.type)) / (\(event.flavor))`")
                                .frame(alignment: .leading)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    HStack{
                        Text("\u{2022} **Target process name:**")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(targetProcName)`")
                                .frame(alignment: .leading)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    VStack(alignment: .leading) {
                        Text("\u{2022} **Target process path:**")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(targetProcPath)`")
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    if let signingId = event.target?.signing_id, !signingId.isEmpty {
                        HStack {
                            Text("\u{2022} **Signing ID:**")
                                .padding([.leading], 5.0)
                            GroupBox {
                                Text("`\(signingId)`")
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
                    Button("**Target audit tokens**") {
                        showTargetAuditTokens.toggle()
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
        }.sheet(isPresented: $showTargetAuditTokens) {
            AuditTokenView(audit_token: auditToken)
            Button("**Dismiss**") {
                showTargetAuditTokens.toggle()
            }.buttonStyle(.borderedProminent).tint(.pink).opacity(0.8).padding(.trailing).padding(.bottom)
        }
    }
}

