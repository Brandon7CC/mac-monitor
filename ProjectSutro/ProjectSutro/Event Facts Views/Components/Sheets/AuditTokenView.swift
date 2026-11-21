//
//  AuditTokenView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 1/17/23.
//

import SwiftUI
import SutroESFramework


// MARK: - Audit tokens
/// A process's audit tokens, for a sheet in Event Facts: its own, and its responsible and parent processes' when
/// they're given.
struct AuditTokenView: View {
    /// The process's own audit token.
    var audit_token: String
    /// The audit tokens of the process responsible for it and of its parent, or `nil` to leave one out.
    var responsible_audit_token, parent_audit_token: String?

    var body: some View {
        VStack(alignment: .leading) {
            Form {
                Section {
                    Text("**Audit tokens**").font(.title2)
                    Divider()
                    Fact("Process audit token", audit_token)
                    if let responsible_audit_token { Fact("Responsible audit token", responsible_audit_token) }
                    if let parent_audit_token { Fact("Parent audit token", parent_audit_token) }
                }
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity).padding(.all)
    }
}

extension AuditTokenView {
    /// A process's audit tokens, with its responsible and parent processes'.
    ///
    /// - Parameter process: The process.
    init(process: ESProcess) {
        self.init(audit_token: process.audit_token_string,
                  responsible_audit_token: process.responsible_audit_token_string,
                  parent_audit_token: process.parent_audit_token_string)
    }
}
