//
//  SystemLoginLoginMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

struct SystemLoginLoginMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    private var event: ESLoginLoginEvent {
        esSystemEvent.event.login_login!
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            LoginLoginEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Label("**Username:**", systemImage: "person.fill")
                            .padding([.leading], 5.0)
                        GroupBox {
                            if event.has_uid {
                                Text("`\(event.username) (\(event.uid))`")
                            } else {
                                Text("`\(event.username)`")
                            }
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    HStack {
                        Text("\u{2022} **Success:**")
                        GroupBox {
                            Text("`\(event.succcess ? "Yes" : "No")`")
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    if event.failure_message != nil && !event.failure_message!.isEmpty {
                        HStack {
                            Text("\u{2022} **Failure message:**")
                            GroupBox {
                                Text("`\(event.failure_message!)`")
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
