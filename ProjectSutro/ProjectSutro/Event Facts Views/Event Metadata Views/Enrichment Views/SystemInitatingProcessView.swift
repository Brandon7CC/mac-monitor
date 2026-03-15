//
//  SysteminitiatingProcessView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework


// MARK: - Initiating process
struct SystemInitiatingProcessView: View {
    var selectedMessage: ESMessage
    @State private var initiatingMetadataExpanded: Bool = false
    @State private var showAuditTokens: Bool = false
    
    private var eventTimeStamp: String {
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSS'Z'"
        return dateFormatter.string(from: selectedMessage.message_darwin_time)
    }
    
    var body: some View {
        List {
            VStack(alignment: .leading) {
                Label("**Message details**", systemImage: "envelope.badge.shield.half.filled")
                    .font(.title2)
                
                GroupBox {
                    HStack {
                        Label("**Message timestamp:**", systemImage: "clock")
                        GroupBox {
                            Text("`\(selectedMessage.time)`")
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    HStack {
                        Label("**Version:**", systemImage: "number")
                        GroupBox {
                            Text("`\(selectedMessage.version)`")
                        }
                        Label("**Thread ID:**", systemImage: "scribble")
                        GroupBox {
                            Text("`\(String(selectedMessage.thread.thread_id))`")
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    HStack {
                        Text("\u{2022} **Resulting event type:**")
                        GroupBox {
                            SystemEventTypeLabel(message: selectedMessage)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
                
                
                GroupBox {
                    VStack(alignment: .leading) {
                        HStack {
                            Text("\u{2022} **Parent PID:**")
                            GroupBox {
                                Text("`\(String(selectedMessage.process.pid))`")
                            }
                            
                            HStack {
                                Image(systemName: "person.fill")
                                Text("**Parent user:**")
                                InitiatingUserView(selectedMessage: selectedMessage)
                            }.frame(maxWidth: .infinity, alignment: .leading)
                        }
                        
                        HStack {
                            Text("\u{2022} **Parent process name:**")
                                .font(.title3)
                            GroupBox {
                                Text("`\(selectedMessage.process.executable?.name ?? "")`")
                            }
                        }
                        
                        HStack {
                            Text("\u{2022} **Parent process path:**")
                            GroupBox {
                                Text("`\(selectedMessage.process.executable?.path ?? "")`")
                                    .lineLimit(30)
                            }
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
                
                Label("**Code signing details**", systemImage: "signature")
                    .font(.title2)
                    .padding([.leading], 5.0)
                GroupBox {
                    VStack(alignment: .leading) {
                        HStack {
                            if selectedMessage.process.signing_id != nil || !selectedMessage.process.signing_id!.isEmpty {
                                Text("\u{2022} **Process signing ID:**")
                                GroupBox {
                                    VStack(alignment: .leading) {
                                        Text("`\(selectedMessage.process.signing_id ?? "")`")
                                    }
                                }
                            } else {
                                GroupBox {
                                    Text("Code object is not signed at all")
                                        .frame(alignment: .leading)
                                }
                            }
                        }
                        
                        HStack {
                            Text("\u{2022} **`SHA256` Code directory hash:**").font(.title3)
                            GroupBox {
                                Text("`\(String(selectedMessage.process.cdhash ?? ""))`")
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
                
                Divider()
                
                Group {
                    Label("**Context items**", systemImage: "folder.badge.plus").font(.title2).padding([.leading], 5.0)
                    GroupBox {
                        HStack {
                            Button("**Audit tokens**") {
                                showAuditTokens.toggle()
                            }
                        }.frame(maxWidth: .infinity, alignment: .center).padding(.all)
                    }
                }
        }
            .textSelection(.enabled)
        }.frame(maxHeight: .infinity, alignment: .topLeading)
            .sheet(isPresented: $showAuditTokens) {
            AuditTokenView(
                audit_token: selectedMessage.process.audit_token_string,
                responsible_audit_token: selectedMessage.process.responsible_audit_token_string,
                parent_audit_token: selectedMessage.process.parent_audit_token_string
            )
            Button("**Dismiss**") {
                showAuditTokens.toggle()
            }.padding(.bottom)
        }
    }
}
