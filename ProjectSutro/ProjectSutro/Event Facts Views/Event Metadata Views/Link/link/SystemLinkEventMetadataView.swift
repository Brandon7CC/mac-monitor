//
//  SystemLinkEventMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/3/23.
//

import SwiftUI
import SutroESFramework

struct SystemLinkEventMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    private var event: ESLinkEvent {
        esSystemEvent.event.link!
    }
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if esSystemEvent.event.link != nil {
            eventContent
        }
    }

    @ViewBuilder
    private var eventContent: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            FileLinkEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    if let srcPath = event.source.path {
                        VStack(alignment: .leading) {
                            Text("\u{2022} Source file path:")
                                .bold()
                                .padding([.leading], 5.0)
                            GroupBox {
                                Text(srcPath)
                                    .monospaced()
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                    
                    if let tgtPath = esSystemEvent.target_path {
                        VStack(alignment: .leading) {
                            Text("\u{2022} Destination file path:")
                                .bold()
                                .padding([.leading], 5.0)
                            GroupBox {
                                Text(tgtPath)
                                    .monospaced()
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
                
                Divider()
                
                HStack {
                    VStack(alignment: .leading) {
                        Text("\u{2022} Source file name:")
                            .bold()
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text(event.source.name)
                                .monospaced()
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    Image(systemName: "arrow.right")
                    VStack(alignment: .leading) {
                        Text("\u{2022} Destination file name:")
                            .bold()
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text(event.target_filename)
                                .monospaced()
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
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
