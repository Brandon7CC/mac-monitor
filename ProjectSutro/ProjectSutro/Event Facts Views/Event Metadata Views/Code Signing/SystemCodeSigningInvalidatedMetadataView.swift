//
//  SystemCodeSigningInvalidatedMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/4/23.
//

import SwiftUI
import SutroESFramework

struct SystemCodeSigningInvalidatedMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if esSystemEvent.event.cs_invalidated != nil {
            eventContent
        }
    }

    @ViewBuilder
    private var eventContent: some View {
        VStack(alignment: .leading) {
            CodeSignatureInvalidatedEventLabelView(message: esSystemEvent).font(.title2).padding([.top, .leading], 5.0)
            
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

