//
//  SystemSetModeMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/29/25.
//

import SwiftUI
import SutroESFramework

struct SystemSetModeMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    private var event: ESSetModeEvent {
        esSystemEvent.event.setmode!
    }
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if esSystemEvent.event.setmode != nil {
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
                        Text("\u{2022} Mode:")
                            .bold()
                        GroupBox {
                            Text("\(String(event.mode))")
                        }
                    }
                    
                    if let path = event.target.path {
                        HStack {
                            Text("\u{2022} File path:")
                                .bold()
                            GroupBox {
                                Text(path)
                                    .monospaced()
                            }
                        }
                    }
                }.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
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
