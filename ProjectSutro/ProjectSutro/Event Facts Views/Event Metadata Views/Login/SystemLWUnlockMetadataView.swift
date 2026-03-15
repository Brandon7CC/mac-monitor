//
//  SystemLWUnlockMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/18/23.
//

import SwiftUI
import SutroESFramework

struct SystemLWUnlockMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    private var event: ESLWUnlockEvent {
        esSystemEvent.event.lw_session_unlock!
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            LoginWindowUnlockEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Label("**Username:**", systemImage: "person.fill")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(event.username)`")
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    HStack {
                        Text("\u{2022} **Graphical session ID:**")
                        GroupBox {
                            Text("`\(event.graphical_session_id)`")
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
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
