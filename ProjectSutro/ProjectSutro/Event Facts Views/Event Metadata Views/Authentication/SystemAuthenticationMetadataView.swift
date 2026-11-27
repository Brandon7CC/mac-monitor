//
//  SystemAuthenticationMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/21/26.
//

import SwiftUI
import SutroESFramework
import EndpointSecurity


// MARK: - Authentication
/// What an `authentication` event says: whether it succeeded, how the user was authenticated, who it was for, and the
/// process that asked. Each kind of authentication has its own facts: Open Directory's record and node, Touch ID's
/// mode and user, a token's identifier and key, or Auto Unlock's user and purpose.
struct SystemAuthenticationMetadataView: View {
    /// The event's message.
    let message: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = message.event.authentication {
            EventFactsCard(message: message, target: event.instigator,
                           labelTint: event.success ? .green : .orange) {
                FactsBox {
                    FactRow(name: "Result", value: event.success ? "Succeeded" : "Failed")
                    FactRow(name: "Method", value: "\(Self.method(of: event)) (\(event.type_string ?? "Unknown"))")
                    Self.facts(of: event)
                    Divider().padding([.top, .bottom])
                    AuthenticationInstigatorView(event: event)
                }
            }
        }
    }

    /// - Parameter event: The event.
    /// - Returns: How the user was authenticated, in plain words.
    private static func method(of event: ESAuthenticationEvent) -> String {
        switch es_authentication_type_t(UInt32(truncatingIfNeeded: event.type)) {
        case ES_AUTHENTICATION_TYPE_OD: "Password, checked by Open Directory"
        case ES_AUTHENTICATION_TYPE_TOUCHID: "Touch ID"
        case ES_AUTHENTICATION_TYPE_TOKEN: "Token, such as a smart card"
        case ES_AUTHENTICATION_TYPE_AUTO_UNLOCK: "Apple Watch (Auto Unlock)"
        default: "Unknown"
        }
    }

    /// The facts only this kind of authentication has.
    ///
    /// - Parameter event: The event.
    /// - Returns: The facts.
    @ViewBuilder
    private static func facts(of event: ESAuthenticationEvent) -> some View {
        switch es_authentication_type_t(UInt32(truncatingIfNeeded: event.type)) {
        case ES_AUTHENTICATION_TYPE_OD:
            FactRow(name: "\(event.record_type.nonEmpty ?? "Record") record name", value: event.record_name)
            FactRow(name: "Node name", value: event.node_name)
            if let path = event.db_path.nonEmpty {
                FactRow(name: "Database path", value: path)
            }
        case ES_AUTHENTICATION_TYPE_TOUCHID:
            FactRow(name: "Mode", value: event.touchid_mode_string)
            FactRow(name: "User", value: event.uid.map { uid in
                event.uid_human.nonEmpty.map { "\($0) (\(uid))" } ?? "\(uid)"
            } ?? "Not identified")
        case ES_AUTHENTICATION_TYPE_TOKEN:
            FactRow(name: "Token identifier", value: event.token_id)
            FactRow(name: "Public key hash", value: event.pubkey_hash)
            if let principal = event.kerberos_principal.nonEmpty {
                FactRow(name: "Kerberos principal", value: principal)
            }
        case ES_AUTHENTICATION_TYPE_AUTO_UNLOCK:
            FactRow(name: "User name", value: event.username)
            FactRow(name: "Purpose", value: event.auto_unlock_type_string)
        default:
            EmptyView()
        }
    }
}


// MARK: - Instigator
/// The process that asked for an authentication (the XPC caller, which differs from the process that sent the event):
/// its name, signing ID, code signing type and path. Auto Unlock names none.
struct AuthenticationInstigatorView: View {
    /// The event.
    let event: ESAuthenticationEvent

    var body: some View {
        if let process = event.instigator {
            GroupBox {
                Label("The process that asked for the authentication.", systemImage: "info.square")
            }
            FactRow(name: "Process name", value: process.executable?.name)
            FactRow(name: "Process signing ID", value: process.signing_id.nonEmpty ?? "Unsigned")
            FactRow(name: "Process code signing type", value: process.codesigning_type)
            FactRow(name: "Process path", value: process.executable?.path, stacked: true)
            FactRow(name: "Process audit token", value: process.audit_token_string, stacked: true)
        } else if event.instigator_token != nil {
            Text("Endpoint Security didn't include the process that asked, only its audit token.")
                .font(.caption)
                .foregroundStyle(.secondary)
        } else {
            Text("This kind of authentication names no process that asked for it.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}
