//
//  SystemProcExitMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

struct SystemProcExitMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    var event: ESProcessExitEvent {
        esSystemEvent.event.exit!
    }
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if esSystemEvent.event.exit != nil {
            eventContent
        }
    }

    @ViewBuilder
    private var eventContent: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            ExitEventLabelView(message: esSystemEvent)
                .font(.title2)
                .padding([.top, .leading], 5.0)
            
            GroupBox {
                VStack(alignment: .leading) {
                    GroupBox {
                        HStack {
                            // MARK: Exit code
                            Text("\u{2022} **Exit code:**")
                            GroupBox {
                                Text("`\(event.stat)`")
                            }.frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    
                    // MARK: Process
                    ProcessView(message: esSystemEvent, process: esSystemEvent.process)
                    
                }.frame(maxWidth: .infinity, alignment: .leading)
                
            }
            
            Divider()
            
            Label("**Context items**", systemImage: "folder.badge.plus")
                .font(.title2)
                .padding([.leading], 5.0)
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
