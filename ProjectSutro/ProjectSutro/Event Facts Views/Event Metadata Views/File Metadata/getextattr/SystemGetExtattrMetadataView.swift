//
//  SystemGetXattrMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/17/25.
//

import SwiftUI
import SutroESFramework


struct SystemGetXattrMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    private var event: ESXattrGetEvent {
        esSystemEvent.event.getextattr!
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            IntelligentEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Text("\u{2022} Extended attribute:")
                            .bold()
                        GroupBox {
                            Text(event.extattr)
                                .monospaced()
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} File name:")
                            .bold()
                        GroupBox {
                            Text(event.target.name)
                                .monospaced()
                        }
                    }
                    
                    if !event.target.path.isEmpty {
                        VStack(alignment: .leading) {
                            Text("\u{2022} File path:")
                            GroupBox {
                                Text(event.target.path)
                                    .monospaced()
                                    .lineLimit(30)
                            }
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

