//
//  SystemFDDuplicateMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 2/19/23.
//

import SwiftUI
import SutroESFramework

struct SystemFDDuplicateMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    var event: ESFDDuplicateEvent {
        esSystemEvent.event.dup!
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            FDDuplicateEventLabelView(message: esSystemEvent)
                .font(.title2)
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Text("\u{2022} File name:")
                            .bold()
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text(event.target.name)
                                .monospaced()
                                .frame(alignment: .leading)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    if let path = event.target.path {
                        VStack(alignment: .leading) {
                            Text("\u{2022} File path:")
                                .bold()
                                .padding([.leading], 5.0)
                            GroupBox {
                                Text(path)
                                    .monospaced()
                                    .frame(maxWidth: .infinity, alignment: .leading)
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
            }.padding(.bottom)
        }
    }
}
