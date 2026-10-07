//
//  SystemForkProcMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

// MARK: - Fork event metadata
struct SystemForkProcMetadataView: View {
    var selectedMessage: ESMessage
    
    @State private var showAuditTokens: Bool = false
    
    var forkEvent: ESProcessForkEvent {
        selectedMessage.event.fork!
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            ForkEventLabelView(message: selectedMessage)
                .font(.title2)
            
            // MARK: Process
            ProcessView(message: selectedMessage, process: forkEvent.child)
            
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
                audit_token: forkEvent.child.audit_token_string,
                responsible_audit_token: forkEvent.child.responsible_audit_token_string,
                parent_audit_token: forkEvent.child.parent_audit_token_string
            )
            Button("**Dismiss**") {
                showAuditTokens.toggle()
            }.padding(.bottom)
        }
        
    }
}
