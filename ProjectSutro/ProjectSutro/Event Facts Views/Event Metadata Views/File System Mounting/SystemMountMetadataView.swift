//
//  SystemMountMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

struct SystemMountMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    private var event: ESMountEvent {
        esSystemEvent.event.mount!
    }
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if esSystemEvent.event.mount != nil {
            eventContent
        }
    }

    @ViewBuilder
    private var eventContent: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            MountEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Text("\u{2022} **Source path:**")
                        GroupBox {
                            Text(event.statfs.f_mntfromname)
                                .monospaced()
                                .lineLimit(10)
                        }
                    }
                    HStack {
                        Text("\u{2022} **Mount directory:**")
                        GroupBox {
                            Text(event.statfs.f_mntonname)
                                .monospaced()
                                .lineLimit(10)
                        }
                    }
                    HStack {
                        Text("\u{2022} **Type:**")
                        GroupBox {
                            Text(event.disposition_string.droppingPrefix("ES_MOUNT_DISPOSITION_"))
                                .monospaced()
                        }
                        Text("\u{2022} **Total files:**")
                        GroupBox {
                            Text(String(event.statfs.f_files))
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


