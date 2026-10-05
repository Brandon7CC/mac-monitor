//
//  SystemXProtectRemediateMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework


struct SystemXProtectRemediateMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    private var event: ESXProtectRemediate {
        esSystemEvent.event.xp_malware_remediated!
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            XProtectMalwareRemediatedEventLabelView(message: esSystemEvent)
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
                        Text("\u{2022} **Action type:**")
                        GroupBox {
                            Text("`\(event.action_type)`")
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} **Was successful?**")
                        GroupBox {
                            Text("`\(event.success ? "Yes" : "No")`")
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} **Description:**")
                        GroupBox {
                            Text("`\(event.result_description)`")
                                .lineLimit(15)
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} **Remediated path:**")
                        GroupBox {
                            Text("`\(event.remediated_path ?? "")`")
                                .lineLimit(10)
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
