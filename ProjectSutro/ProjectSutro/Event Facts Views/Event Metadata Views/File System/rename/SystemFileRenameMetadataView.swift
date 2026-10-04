//
//  SystemFileRenameMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 2/17/23.
//

import SwiftUI
import SutroESFramework

struct SystemFileRenameMetadataView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    var event: ESFileRenameEvent {
        esSystemEvent.event.rename!
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            FileRenameEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                if event.is_quarantined == 0 && event.destination_path.hasSuffix(".app") {
                    VStack(alignment: .leading) {
                        HStack {
                            Image(systemName: "hand.raised.app")
                                .font(Font.system(size: 10, weight: .bold))
                                .symbolRenderingMode(.palette)
                                .foregroundStyle(.red)
                                .help("An unquarantined application bundle was inflated as a result of an unarchive operation")
                            Text("**Application inflated:**")
                        }.padding([.leading], 5.0)
                        
                        GroupBox {
                            VStack(alignment: .leading) {
                                HStack {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .symbolRenderingMode(.palette)
                                        .foregroundStyle(.black, .yellow)
                                    Text("An application bundle was inflated as a result of an unarchive operation. Identify in context where this app came from. If the original archive was quarantined this should have been as well, but was not.")
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .lineLimit(20)
                                }
                            }.frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    Divider()
                }
                
                VStack(alignment: .leading) {
                    GroupBox {
                        HStack {
                            Text("\u{2022} Destination type:")
                                .bold()
                            Text("\(event.destination_type_string.replacingOccurrences(of: "ES_DESTINATION_TYPE_", with: ""))")
                                .monospaced()
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} Destination file name:")
                            .bold()
                            .padding([.leading], 5.0)
                        
                        GroupBox {
                            Text(event.destination_file_name)
                                .monospaced()
                        }
                        
                        FileQuarantineStatusLabelView(isQuarantined: Int(event.is_quarantined))
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    
                    HStack {
                        FileExistsLabel(title: "**Destination Path:**", path: event.destination_path)
                        GroupBox {
                            Text(event.destination_path)
                                .monospaced()
                                .lineLimit(10)
                        }
                    }
                    
                    if let sourcePath = event.source.path {
                        HStack {
                            FileExistsLabel(title: "**Source path:**", path: sourcePath)
                            GroupBox {
                                Text(sourcePath)
                                    .monospaced()
                                    .lineLimit(10)
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
