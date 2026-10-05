//
//  SystemRemoteThreadCreateMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/4/23.
//

import SwiftUI
import SutroESFramework

struct SystemRemoteThreadCreateMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    @State private var showTargetAuditTokens: Bool = false
    
    private var event: ESRemoteThreadCreateEvent {
        esSystemEvent.event.remote_thread_create!
    }
    
    private var targetName: String {
        event.target.executable?.name ?? "Unknown"
    }
    
    private var targetPath: String {
        event.target.executable?.path ?? "Unknown"
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
            RemoteThreadCreateEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    
                    ThreadStateFactsView(state: event.thread_state, flavorName: event.thread_state_string)
                    FactRow(name: "Target process name", value: targetName, style: .monospaced)
                    FactRow(name: "Target process path", value: targetPath, stacked: true, style: .monospaced)
                    if let signingId = targetSigningId, !signingId.isEmpty {
                        FactRow(name: "Signing ID", value: signingId, style: .monospaced)
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

