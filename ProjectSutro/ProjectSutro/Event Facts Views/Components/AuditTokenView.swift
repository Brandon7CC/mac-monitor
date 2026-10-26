//
//  AuditTokenView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework


struct AuditTokenView: View {
    var audit_token: String
    var responsible_audit_token, parent_audit_token: String?
    
    var body: some View {
        VStack(alignment: .leading) {
            Form {
                Section {
                    Text("**Audit tokens**").font(.title2)
                    Divider()
                    Text("\u{2022} **Process audit token:**")
                    GroupBox {
                        Text("`\(audit_token)`")
                    }
                    
                    if responsible_audit_token != nil {
                        Text("\u{2022} **Responsible audit token:**")
                        GroupBox {
                            Text("`\(responsible_audit_token!)`")
                        }
                    }
                    
                    if parent_audit_token != nil {
                        Text("\u{2022} **Parent audit token:**")
                        GroupBox {
                            Text("`\(parent_audit_token!)`")
                        }
                    }
                }
            }
            
        }.frame(maxWidth: .infinity, maxHeight: .infinity).padding(.all)
    }
}
