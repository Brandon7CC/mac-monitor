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
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if esSystemEvent.event.profile_add != nil {
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
                    
                    if let profile = event.profile {
                        VStack(alignment: .leading) {
                            Text("\u{2022} Profile display name:")
                                .bold()
                                .padding([.leading], 5.0)
                            GroupBox {
                                Text(profile.display_name)
                                    .monospaced()
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                        
                        VStack(alignment: .leading) {
                            Text("\u{2022} Profile identifer:")
                                .bold()
                                .padding([.leading], 5.0)
                            GroupBox {
                                Text(profile.identifier)
                                    .monospaced()
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                        
                        VStack(alignment: .leading) {
                            Text("\u{2022} Organization:")
                                .bold()
                                .padding([.leading], 5.0)
                            GroupBox {
                                Text(profile.organization)
                                    .monospaced()
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                        
                        HStack {
                            Text("\u{2022} Source type:")
                                .bold()
                                .padding([.leading], 5.0)
                            GroupBox {
                                Text("\(profile.installSourceShortName) (\(profile.install_source))")
                                    .monospaced()
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            Text("\u{2022} Is update:")
                                .bold()
                                .padding([.leading], 5.0)
                            GroupBox {
                                Text("\(event.is_update ? "Yes" : "No")")
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
