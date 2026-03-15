//
//  SystemTCCModifyMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 8/18/25.
//

import SwiftUI
import SutroESFramework


struct SystemTCCModifyMetadataView: View {
    var message: ESMessage
    @State private var showAuditTokens: Bool = false
    @State private var showInstigator: Bool = false
    
    private var event: ESTCCModifyEvent {
        message.event.tcc_modify!
    }
    
    private var identitySuffix: String {
        event.identity_type_string.replacingOccurrences(of: "ES_TCC_IDENTITY_TYPE_", with: "")
    }
    
    private var updateSuffix: String {
        event.update_type_string.replacingOccurrences(of: "ES_TCC_EVENT_TYPE_", with: "")
    }
    
    private var rightSuffix: String {
        event.right_string.replacingOccurrences(of: "ES_TCC_AUTHORIZATION_RIGHT_", with: "")
    }
    
    private var reasonSuffix: String {
        event.reason_string.replacingOccurrences(of: "ES_TCC_AUTHORIZATION_REASON_", with: "")
    }
    
    private var rightSuccess: Bool {
        switch(rightSuffix){
        case "DENIED":
            return false
        case "UNKNOWN":
            return false
        default:
            return true
        }
    }

    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            SystemEventTypeLabel(message: message)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        HStack {
                            Text("\u{2022} **Update type:**")
                            GroupBox {
                                Text("`\(updateSuffix)`")
                            }
                        }
                        
                        HStack {
                            Text("\u{2022} **Reason:**")
                            GroupBox {
                                Text("`\(reasonSuffix)`")
                            }
                        }
                        
                        HStack {
                            Text("\u{2022} **Service name:**")
                            GroupBox {
                                Text("`\(event.service)`")
                            }
                        }
                    }
                    
                    
                    HStack {
                        HStack {
                            Text("\u{2022} **Identity type:**")
                            GroupBox {
                                Text("`\(identitySuffix)`")
                            }
                        }
                        
                        HStack {
                            Text("\u{2022} **Identity:**")
                            GroupBox {
                                Text("`\(event.identity)`")
                            }
                        }
                    }
                    
                    HStack {
                        Label("Right", systemImage: rightSuccess ? "checkmark.circle" : "xmark.circle")
                            .bold()
                        GroupBox {
                            Text("`\(rightSuffix)`")
                        }
                    }
                    
                    if let instigator = event.instigator,
                       let executable = instigator.executable {
                        Divider()
                        
                        VStack(alignment: .leading) {
                            Text("Instigator")
                                .font(.title3)
                                .bold()
                            
                            HStack {
                                Text("\u{2022} **Instigator name:**")
                                GroupBox {
                                    Text("`\(executable.name)`")
                                }
                                Text("\u{2022} **PID:**")
                                GroupBox {
                                    Text("`\(String(instigator.pid))`")
                                }
                                Text("\u{2022} **GID:**")
                                GroupBox {
                                    Text("`\(String(instigator.group_id))`")
                                }
                            }.frame(maxWidth: .infinity, alignment: .leading)
                            
                            
                            HStack {
                                Text("\u{2022} **Instigator path:**")
                                GroupBox {
                                    Text("`\(executable.path)`")
                                        .lineLimit(10)
                                }
                            }.frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    
                    
                    
                    if let responsible = event.responsible,
                       let executable = responsible.executable {
                        Divider()
                        
                        VStack(alignment: .leading) {
                            Text("Responsible")
                                .font(.title3)
                                .bold()
                            
                            HStack {
                                Text("\u{2022} **Responsible name:**")
                                GroupBox {
                                    Text("`\(executable.name)`")
                                }
                                Text("\u{2022} **PID:**")
                                GroupBox {
                                    Text("`\(String(responsible.pid))`")
                                }
                                Text("\u{2022} **GID:**")
                                GroupBox {
                                    Text("`\(String(responsible.group_id))`")
                                }
                            }.frame(maxWidth: .infinity, alignment: .leading)
                            
                            
                            HStack {
                                Text("\u{2022} **Responsible path:**")
                                GroupBox {
                                    Text("`\(executable.path)`")
                                        .lineLimit(10)
                                }
                            }.frame(maxWidth: .infinity, alignment: .leading)
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
                audit_token: message.process.audit_token_string,
                responsible_audit_token: message.process.responsible_audit_token_string,
                parent_audit_token: message.process.parent_audit_token_string
            )
            Button("**Dismiss**") {
                showAuditTokens.toggle()
            }.padding(.bottom)
        }
    }
}
