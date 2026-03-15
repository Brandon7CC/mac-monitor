//
//  SystemAuthorizationPetitionMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/27/23.
//

import SwiftUI
import SutroESFramework


struct AuthProcsView: View {
    var event: ESAuthorizationPetitionEvent
    
    var instigator: ESProcess? {
        event.instigator
    }
    
    var petitioner: ESProcess? {
        event.petitioner
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            if let instigator = instigator,
               let petitioner = petitioner,
               let instigatorSigningId = instigator.signing_id,
               let petitionerSigningId = petitioner.signing_id,
               let instigatorExe = instigator.executable,
               let petitionerExe = petitioner.executable {
                
                if instigatorSigningId != petitionerSigningId {
                    HStack {
                        Text("\u{2022} Instigator process name:")
                            .bold()
                        GroupBox {
                            Text(instigatorExe.name)
                                .monospaced()
                        }
                    }
                    VStack(alignment: .leading) {
                        Text("\u{2022} Instigator process path:")
                            .bold()
                        GroupBox {
                            Text(instigatorExe.path)
                                .monospaced()
                                .font(.title3).frame(maxWidth: .infinity, alignment: .leading)
                                .lineLimit(30)
                        }
                    }
                    HStack {
                        Text("\u{2022} Instigator process signing ID:")
                            .bold()
                        GroupBox {
                            Text(instigatorSigningId)
                                .monospaced()
                        }
                    }
                    
                    
                    Divider().padding(.vertical, 10)
                    
                    HStack {
                        Text("\u{2022} Petitioner process name:")
                            .bold()
                        GroupBox {
                            Text(petitionerExe.name)
                                .monospaced()
                        }
                    }
                    VStack(alignment: .leading) {
                        Text("\u{2022} Petitioner process path:")
                            .bold()
                        GroupBox {
                            Text(petitionerExe.path)
                                .monospaced()
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .lineLimit(30)
                        }
                    }
                    HStack {
                        Text("\u{2022} Petitioner process signing ID:")
                            .bold()
                        GroupBox {
                            Text(petitionerSigningId)
                                .monospaced()
                        }
                    }
                    
                    Divider().padding(.vertical, 10)
                }
            } else if let instigatorExe = instigator?.executable {
                GroupBox {
                    Label("The processes petitioning and instigating are the same:", systemImage: "info.square")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                HStack {
                    Text("\u{2022} Process name:")
                        .bold()
                    GroupBox {
                        Text(instigatorExe.name)
                            .monospaced()
                    }
                }
                VStack(alignment: .leading) {
                    Text("\u{2022} Process path:")
                        .bold()
                    GroupBox {
                        Text(instigatorExe.path)
                            .monospaced()
                            .lineLimit(nil)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                HStack {
                    Text("\u{2022} Process signing ID:")
                        .bold()
                    GroupBox {
                        Text(instigator?.signing_id ?? "")
                            .monospaced()
                    }
                }
                Divider().padding(.vertical, 10)
            }
        }
    }
}

struct SystemAuthorizationPetitionMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    var event: ESAuthorizationPetitionEvent {
        esSystemEvent.event.authorization_petition!
    }
    
    // Helper struct for Table
    private struct IdentifiableString: Identifiable {
        let id = UUID()
        let value: String
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            OrangeEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    AuthProcsView(event: event)
                    
                    Text("Flags:")
                        .bold()
                    GroupBox {
                        Label("Flags are defined as part of the Security framework in: `Authorization/Authorization.h`", systemImage: "info.square")
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    GroupBox {
                        Table(event.flags_array.map { IdentifiableString(value: $0) }) {
                            TableColumn("Flag", value: \.value)
                                .width(min: 200)
                        }
                        .monospaced()
                        .frame(minHeight: 100, maxHeight: 200)
                    }
                    
                    Divider()
                        .padding(.vertical, 10)
                    
                    Text("Rights requested:")
                        .bold()
                    GroupBox {
                        Label("Default right definitions: `/System/Library/Security/authorization.plist` and runtime authorization database: `/var/db/auth.db`.", systemImage: "info.square")
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    GroupBox {
                        Table(event.rights.map { IdentifiableString(value: $0) }) {
                            TableColumn("Right", value: \.value)
                                .width(min: 200)
                        }
                        .monospaced()
                        .frame(minHeight: 100, maxHeight: 200)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding([.leading, .trailing], 10)
            }
            
            Divider().padding(.vertical, 10)
            
            Label("**Context items**", systemImage: "folder.badge.plus").font(.title2).padding([.leading], 5.0)
            GroupBox {
                HStack {
                    Button("**Audit tokens**") {
                        showAuditTokens.toggle()
                    }
                }.frame(maxWidth: .infinity, alignment: .center).padding(.all)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .sheet(isPresented: $showAuditTokens) {
            VStack {
                AuditTokenView(
                    audit_token: esSystemEvent.process.audit_token_string,
                    responsible_audit_token: esSystemEvent.process.responsible_audit_token_string,
                    parent_audit_token: esSystemEvent.process.parent_audit_token_string
                )
                Button("Dismiss") {
                    showAuditTokens.toggle()
                }.padding(.bottom)
            }
        }
    }
}
