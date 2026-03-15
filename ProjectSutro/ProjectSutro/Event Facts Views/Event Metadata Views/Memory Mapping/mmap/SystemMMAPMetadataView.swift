//
//  SystemMMAPMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework

struct SystemMMAPMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    private var event: ESMMapEvent {
        esSystemEvent.event.mmap!
    }
    
    private var sourcePath: String {
        event.source.path
    }
    
    private var protection: Int32 {
        event.protection
    }
    
    private var maxProtection: Int32 {
        event.max_protection
    }
    
    private var flags: Int32 {
        event.flags
    }
    
    private var filePos: Int {
        event.file_pos
    }
    
    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            MMAPEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Text("\u{2022} **File path mapped:**")
                        GroupBox {
                            Text("`\(sourcePath)`")
                                .lineLimit(10)
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} **Protection:**")
                        GroupBox {
                            Text("`\(protection)`")
                                .lineLimit(10)
                        }
                        
                        Text("\u{2022} **Max protection:**")
                        GroupBox {
                            Text("`\(maxProtection)`")
                                .lineLimit(10)
                        }
                        
                        Text("\u{2022} **Flags:**")
                        GroupBox {
                            Text("`\(flags)`")
                                .lineLimit(10)
                        }
                        
                        Text("\u{2022} **File offset/position:**")
                        GroupBox {
                            Text("`\(filePos)`")
                                .lineLimit(10)
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
