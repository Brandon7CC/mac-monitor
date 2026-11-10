//
//  SystemAuthorizationPetitionMetadataView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/27/23.
//

import SwiftUI
import SutroESFramework


// MARK: - Authorization processes
/// The processes behind an authorization petition or judgement: the one that instigated it and the one that
/// petitioned. One process when both are known and have the same audit token, or else each one that's known.
struct AuthorizationProcessesView: View {
    /// The process that instigated the petition, or `nil`.
    let instigator: ESProcess?
    /// The process that petitioned, or `nil`.
    let petitioner: ESProcess?

    var body: some View {
        VStack(alignment: .leading) {
            if let instigator, let petitioner, instigator.audit_token_string == petitioner.audit_token_string {
                GroupBox {
                    Label("The processes petitioning and instigating are the same:", systemImage: "info.square")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                processFacts(instigator, role: "Process")
                Divider().padding(.vertical, 10)
            } else {
                if let instigator {
                    processFacts(instigator, role: "Instigator process")
                    Divider().padding(.vertical, 10)
                }
                if let petitioner {
                    processFacts(petitioner, role: "Petitioner process")
                    Divider().padding(.vertical, 10)
                }
            }
        }
    }

    /// A process's name, path, and signing ID, or "Unsigned" when it has none.
    ///
    /// - Parameters:
    ///   - process: The process.
    ///   - role: What the facts' names start with, such as "Instigator process".
    /// - Returns: The process's facts.
    @ViewBuilder
    private func processFacts(_ process: ESProcess, role: String) -> some View {
        FactRow(name: "\(role) name", value: process.executable?.name, style: .monospaced)
        if let path = process.executable?.path {
            FactRow(name: "\(role) path", value: path, stacked: true, style: .monospaced)
        }
        FactRow(name: "\(role) signing ID", value: process.signing_id.nonEmpty ?? "Unsigned", style: .monospaced)
    }
}


// MARK: - Petition
/// What an `authorization_petition` event says: the processes behind it, its flags, and the rights it requested.
struct SystemAuthorizationPetitionMetadataView: View {
    var esSystemEvent: ESMessage

    /// Nothing for an event that's gone, as a Clear's events are while the views let go of them.
    var body: some View {
        if let event = esSystemEvent.event.authorization_petition {
            EventFactsCard(message: esSystemEvent) {
                FactsBox {
                    AuthorizationProcessesView(instigator: event.instigator, petitioner: event.petitioner)

                    Text("Flags:")
                        .bold()
                    GroupBox {
                        Label("""
                              Flags are defined as part of the Security framework in: \
                              `Authorization/Authorization.h`
                              """, systemImage: "info.square")
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    GroupBox {
                        FactsGrid(Array(event.flags_array.enumerated()), id: \.offset,
                                  columns: .init("Flag") { $0.element })
                    }

                    Divider()
                        .padding(.vertical, 10)

                    Text("Rights requested:")
                        .bold()
                    GroupBox {
                        Label("""
                              Default right definitions: `/System/Library/Security/authorization.plist` and \
                              runtime authorization database: `/var/db/auth.db`.
                              """, systemImage: "info.square")
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    GroupBox {
                        FactsGrid(Array(event.rights.enumerated()), id: \.offset,
                                  columns: .init("Right") { $0.element })
                    }
                }
            }
        }
    }
}
