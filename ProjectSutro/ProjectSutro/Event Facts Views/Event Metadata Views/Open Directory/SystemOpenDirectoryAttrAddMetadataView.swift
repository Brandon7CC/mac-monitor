//
//  SystemOpenDirectoryAttrAddMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/28/23.
//

import SwiftUI
import SutroESFramework

struct ODAttrAddProcView: View {
    var esSystemEvent: ESMessage
    
    private var event: ESODAttributeValueAddEvent {
        esSystemEvent.event.od_attribute_value_add!
    }
    
    var body: some View {
        GroupBox {
            Label("The process responsible for adding a value to a record.", systemImage: "info.square")
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        
        HStack {
            Text("\u{2022} **Process name:**").font(.title3)
            GroupBox {
                Text("`\(event.instigator_process_name ?? "Unknown")`")
                    .font(.title3)
            }
        }
        
        HStack {
            Text("\u{2022} **Process signing ID:**").font(.title3)
            GroupBox {
                Text("`\(event.instigator_process_name ?? "Unknown")`")
                    .font(.title3)
            }
        }
        
        
        VStack(alignment: .leading) {
            Text("\u{2022} **Process path:**").font(.title3)
            GroupBox {
                Text("`\(event.instigator_process_path ?? "Unknown")`")
                    .font(.title3)
                    .lineLimit(nil)
                    .frame(maxWidth: nil, maxHeight: nil)
            }
        }
        
        
        Divider().padding([.top, .bottom])
    }
}

struct SystemOpenDirectoryAttrAddMetadataView: View {
    var esSystemEvent: ESMessage
    @State private var showAuditTokens: Bool = false
    
    private var event: ESODAttributeValueAddEvent {
        esSystemEvent.event.od_attribute_value_add!
    }

    var body: some View {
        VStack(alignment: .leading) {
            // MARK: Event label
            OrangeEventLabelView(message: esSystemEvent)
                .font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    HStack {
                        Text("\u{2022} **Attribute name:**")
                        GroupBox {
                            Text("`\(event.attribute_name ?? "Unknown")`")
                        }
                    }
                    
                    HStack {
                        Text("\u{2022} **Attribute value:**")
                        GroupBox {
                            Text("`\(event.attribute_value ?? "Unknown")`")
                        }
                    }
                    
                    if !event.record_type.isEmpty {
                        HStack {
                            Text("\u{2022} **\(event.record_type) record name:**")
                            GroupBox {
                                Text("`\(event.record_name ?? "")`")
                            }
                        }
                    }

                    VStack(alignment: .leading) {
                        Text("\u{2022} **Node name:**")
                        GroupBox {
                            Text("`\(event.node_name ?? "Unknown")`")
                                .lineLimit(nil)
                                .frame(maxWidth: nil, maxHeight: nil)
                        }
                    }
                    
                    if event.db_path != nil && !event.db_path!.isEmpty {
                        HStack {
                            Text("\u{2022} **Database path:**")
                            GroupBox {
                                Text("`\(event.db_path ?? "Unknown")`")
                            }
                        }
                    }
                    
                    if event.error_code != 0 {
                        HStack {
                            Text("\u{2022} **Error:**")
                            GroupBox {
                                Text("`\(try! AttributedString(markdown: event.error_code_human!))`")
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
