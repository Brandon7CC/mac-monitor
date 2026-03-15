//
//  SystemUIPCBindMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/1/25.
//

import SwiftUI
import SutroESFramework


struct SystemUIPCBindMetadataView: View {
    var message: ESMessage
    @State private var showAuditTokens: Bool = false
    @State private var showInstigator: Bool = false
    
    private var event: ESUIPCBindEvent {
        message.event.uipc_bind!
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            SystemEventTypeLabel(message: message)
                .font(.title2)
                
            
            GroupBox {
                VStack(alignment: .leading) {
                    if !event.dir.path.isEmpty {
                        let path = URL(fileURLWithPath: event.dir.path).appendingPathComponent(
                            event.filename
                        ).path()
                        
                        HStack {
                            Text("\u{2022} File path:")
                                .bold()
                            GroupBox {
                                Text(path)
                                    .monospaced()
                            }
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} Mode:")
                            .bold()
                        GroupBox {
                            Text(String(event.mode))
                                .monospaced()
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
