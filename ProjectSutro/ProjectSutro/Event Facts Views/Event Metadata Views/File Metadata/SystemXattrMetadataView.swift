//
//  SystemXattrMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework


struct SystemDeleteXattrMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    private var event: ESXattrDeleteEvent {
        esSystemEvent.event.deleteextattr!
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            DeleteXattrEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Text("\u{2022} **Extended attribute:**")
                        GroupBox {
                            Text("`\(event.xattr!)`")
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} **File name:**")
                        GroupBox {
                            Text("`\(event.file_name!)`")
                        }
                    }
                    
                    VStack(alignment: .leading) {
                        Text("\u{2022} **File path:**")
                        GroupBox {
                            Text("`\(event.file_path!)`")
                                .lineLimit(30)
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

struct SystemSetXattrMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    private var event: ESXattrSetEvent {
        esSystemEvent.event.setextattr!
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            SetXattrEventLabelView(message: esSystemEvent)
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
                    
                    if let path = event.target.path {
                        VStack(alignment: .leading) {
                            Text("\u{2022} File path:")
                            GroupBox {
                                Text(path)
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
