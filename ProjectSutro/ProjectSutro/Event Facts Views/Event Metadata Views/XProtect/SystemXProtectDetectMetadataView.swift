//
//  SystemXProtectDetectMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

struct SystemXProtectDetectMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    var event: ESXProtectDetect {
        esSystemEvent.event.xp_malware_detected!
    }
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if esSystemEvent.event.xp_malware_detected != nil {
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
                    HStack {
                        Text("\u{2022} **Malware Identifier:**")
                        GroupBox {
                            Text("`\(event.malware_identifier)`")
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} **Incident ID:**")
                        GroupBox {
                            Text("`\(event.incident_identifier)`")
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} **Detected path:**")
                        GroupBox {
                            Text("`\(event.detected_path)`")
                                .lineLimit(10)
                        }
                    }
                    
                    if let executable = event.detected_executable {
                        HStack {
                            Text("\u{2022} **Executable path:**")
                            GroupBox {
                                Text(executable)
                                    .monospaced()
                                    .lineLimit(10)
                            }
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} **XProtect version:**")
                        VStack(alignment: .leading) {
                            GroupBox {
                                Text("`\(event.signature_version)`")
                            }
                        }
                        
                    }
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
