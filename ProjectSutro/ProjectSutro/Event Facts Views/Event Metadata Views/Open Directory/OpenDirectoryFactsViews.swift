//
//  OpenDirectoryFactsViews.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/4/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Open Directory facts
/// The facts every Open Directory event shows: its label, the process that instigated it, the event's own facts, and
/// its node and result, with the initiating process's audit tokens as a context item.
struct OpenDirectoryFactsView<EventLabel: View, Facts: View>: View {
    /// The event's message.
    let message: ESMessage
    /// The event.
    let event: ESODEvent
    /// What the instigator did, such as "creating a new user".
    let role: String
    /// The event's label.
    @ViewBuilder let label: EventLabel
    /// The event's own facts, between the instigator and the node.
    @ViewBuilder let facts: Facts
    
    @State private var showAuditTokens = false
    
    var body: some View {
        VStack(alignment: .leading) {
            label.font(.title2)
            
            GroupBox {
                VStack(alignment: .leading) {
                    OpenDirectoryInstigatorView(event: event, role: role)
                    facts
                    OpenDirectoryNodeView(event: event)
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
                audit_token: message.process.audit_token_string,
                responsible_audit_token: message.process.responsible_audit_token_string,
                parent_audit_token: message.process.parent_audit_token_string
            )
            Button("**Dismiss**") {
                showAuditTokens.toggle()
            }.padding(.bottom)
        }
    }
}


/// The process that instigated an Open Directory event (the XPC caller, which can differ from the process that sent
/// the event): its name, signing ID, path and audit token.
struct OpenDirectoryInstigatorView: View {
    /// The event.
    let event: ESODEvent
    /// What the instigator did, such as "creating a new user".
    let role: String
    
    var body: some View {
        GroupBox {
            Label("The process responsible for \(role).", systemImage: "info.square")
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        
        FactRow(name: "Process name", value: event.instigator_process_name)
        FactRow(name: "Process signing ID", value: event.instigator_process_signing_id)
        FactRow(name: "Process path", value: event.instigator_process_path, stacked: true)
        FactRow(name: "Process audit token", value: event.instigator_process_audit_token, stacked: true)
        if event.instigator == nil && event.instigator_token != nil {
            Text("Endpoint Security didn't include the instigator's process, only its audit token.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        
        Divider().padding([.top, .bottom])
    }
}


/// Where an Open Directory event happened and how it ended: its node, the node's database, and its error.
struct OpenDirectoryNodeView: View {
    /// The event.
    let event: ESODEvent
    
    var body: some View {
        FactRow(name: "Node name", value: event.node_name, stacked: true)
        if let dbPath = event.db_path.nonEmpty {
            FactRow(name: "Database path", value: dbPath)
        }
        if event.error_code != 0 {
            HStack {
                Text("\u{2022} **Error:**")
                GroupBox {
                    Text(Self.markdown(event.error_code_human ?? "Unknown"))
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
    }
    
    /// An error's description, whose names are Markdown code spans.
    ///
    /// - Parameter text: The description.
    /// - Returns: The description, formatted; as it is if it isn't valid Markdown.
    private static func markdown(_ text: String) -> AttributedString {
        (try? AttributedString(markdown: text)) ?? AttributedString(text)
    }
}


/// The facts of an `od_group_add` or `od_group_remove` event: the group, and the member added or removed.
struct OpenDirectoryGroupMemberFacts: View {
    /// The event.
    let event: ESODGroupMemberEvent
    
    var body: some View {
        FactRow(name: "Group name", value: event.group_name)
        /// Events recorded before 2.2.0 kept only the member's type.
        if let member = event.member_value {
            FactRow(name: "Member", value: member)
        }
        FactRow(name: "Member type", value: event.member_string)
    }
}
