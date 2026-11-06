//
//  SystemFileCloseMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 4/3/23.
//

import SwiftUI
import SutroESFramework

struct SystemFileCloseMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    private var event: ESFileCloseEvent {
        esSystemEvent.event.close!
    }
    
    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if esSystemEvent.event.close != nil {
            eventContent
        }
    }

    /// Whether the file was written through the descriptor, and whether it was mapped writable: Mac Monitor keeps only
    /// modified closes by default, and a file changed only through a writable mapping closes unmodified. Endpoint
    /// Security reports `was_mapped_writable` from message version 6.
    private var writeFacts: some View {
        HStack {
            Text("\u{2022} **Modified:**")
                .padding([.leading], 5.0)
            GroupBox {
                Text("`\(String(event.modified))`")
            }.help("Whether the file was written through this descriptor before it closed.")

            if esSystemEvent.version >= 6 {
                Text("\u{2022} **Mapped writable:**")
                GroupBox {
                    Text("`\(String(event.was_mapped_writable))`")
                }.help("Whether the file was mapped writable. A file changed only through a writable mapping closes unmodified.")
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
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
                        Text("\u{2022} File name:")
                            .bold()
                            .padding([.leading], 5.0)
                        GroupBox {
                            Text(event.target.name)
                                .monospaced()
                                .frame(alignment: .leading)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    
                    if let path = event.target.path {
                        VStack(alignment: .leading) {
                            Text("\u{2022} File path:")
                                .bold()
                                .padding([.leading], 5.0)
                            GroupBox {
                                Text(path)
                                    .monospaced()
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                    }

                    writeFacts
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
