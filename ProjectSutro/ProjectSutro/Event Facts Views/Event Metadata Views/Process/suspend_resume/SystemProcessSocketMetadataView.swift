//
//  SystemProcessSocketMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/4/23.
//

import SwiftUI
import SutroESFramework

struct SystemProcessSocketMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    @State private var showTargetAuditTokens: Bool = false
    
    var suspendResume: ESProcessSocketEvent {
        esSystemEvent.event.proc_suspend_resume!
    }
    
    var targetProcName: String {
        suspendResume.target?.executable?.name ?? "Unknown"
    }
    
    var targetProcPath: String {
        suspendResume.target?.executable?.path ?? "Unknown"
    }
    
    var targetSigningId: String? {
        suspendResume.target?.signing_id
    }
    
    var targetAuditToken: String {
        suspendResume.target?.audit_token_string ?? ""
    }
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if esSystemEvent.event.proc_suspend_resume != nil {
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
                        Text("\u{2022} **Suspend / resume type:**")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(suspendResume.type_string) (\(suspendResume.type))`")
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
                        Text("\u{2022} **Process path:**")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(targetProcPath)`")
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    
                    if let signingId = targetSigningId, !signingId.isEmpty {
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
            AuditTokenView(audit_token: targetAuditToken)
            Button("**Dismiss**") {
                showTargetAuditTokens.toggle()
            }.buttonStyle(.borderedProminent).tint(.pink).opacity(0.8).padding(.trailing).padding(.bottom)
        }
    }
}

