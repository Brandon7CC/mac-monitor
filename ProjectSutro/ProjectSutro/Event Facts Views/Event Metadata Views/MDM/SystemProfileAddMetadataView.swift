//
//  SystemProfileAddMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/6/23.
//

import SwiftUI
import SutroESFramework

struct SystemProfileAddMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    var event: ESProfileAddEvent {
        esSystemEvent.event.profile_add!
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            ProfileAddEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    VStack(alignment: .leading) {
                        Text("\u{2022} **Profile display name:**")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(event.profile_display_name!)`")
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    VStack(alignment: .leading) {
                        Text("\u{2022} **Profile identifer:**")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(event.profile_identifier!)`")
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    VStack(alignment: .leading) {
                        Text("\u{2022} **Organization:**")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(event.profile_organization!)`")
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    HStack {
                        Text("\u{2022} **Source type:**")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(event.profile_source_type!)`")
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        Text("\u{2022} **Is update:**")
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text("`\(event.is_update ? "Yes" : "No")`")
                                .frame(maxWidth: .infinity, alignment: .leading)
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
