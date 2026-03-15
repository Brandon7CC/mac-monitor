//
//  SystemProcessSignalMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/4/23.
//

import SwiftUI
import SutroESFramework

struct SystemProcessSignalMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    @State private var showTargetAuditTokens: Bool = false
    
    private var event: ESProcessSignalEvent {
        esSystemEvent.event.signal!
    }
    
    private var targetProcessName: String {
        event.target.executable!.name
    }
    
    private var targetProcessPath: String {
        event.target.executable!.path
    }
    
    private var targetSigningId: String? {
        event.target.signing_id
    }
    
    private var targetAuditToken: String {
        event.target.audit_token_string
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            ProcessSignalEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Text("\u{2022} **Signal:**")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(event.signal_name) (\(event.sig))`")
                                .frame(alignment: .leading)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    HStack{
                        Text("\u{2022} **Target process name:**")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(targetProcessName)`")
                                .frame(alignment: .leading)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    VStack(alignment: .leading) {
                        Text("\u{2022} **Target process path:**")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(targetProcessPath)`")
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    if let signingId = targetSigningId, !signingId.isEmpty {
                        HStack {
                            Text("\u{2022} **Signing ID:**")
                                .padding(.leading, 5)
                            
                            GroupBox {
                                Text("`\(signingId)`")
                                    .frame(alignment: .leading)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
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
