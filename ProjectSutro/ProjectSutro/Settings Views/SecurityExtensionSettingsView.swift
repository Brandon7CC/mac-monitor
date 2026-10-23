//
//  SecurityExtensionSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/22/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Settings ▸ Security Extension
/// Settings ▸ Security Extension: the same requirements the checklist shows, a way to look again, and reinstalling or
/// uninstalling the Security Extension.
struct SecurityExtensionSettingsView: View {
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @State private var confirmsUninstall = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                VStack(alignment: .trailing, spacing: 10) {
                    RequirementRows(rows: systemExtensionManager.requirements.rows)
                    Button("Check Again") { systemExtensionManager.refreshRequirements() }
                }
                SettingsSection("Reinstall or uninstall") {
                    VStack(spacing: 0) {
                        ActionRow(title: "Reinstall",
                                  detail: "Asks macOS to activate this copy's Security Extension again.") {
                            Button("Reinstall") { systemExtensionManager.activateSystemExtension() }
                        }
                        Divider().padding(.leading, 14)
                        ActionRow(title: "Uninstall",
                                  detail: "Stops all monitoring. macOS asks for an administrator's password.") {
                            Button("Uninstall…", role: .destructive) { confirmsUninstall = true }
                        }
                    }
                }
            }
            .padding(.vertical, 4)
        }
        .onAppear { systemExtensionManager.refreshRequirements() }
        .confirmationDialog("Uninstall the Security Extension?", isPresented: $confirmsUninstall) {
            Button("Uninstall", role: .destructive) { systemExtensionManager.uninstallSystemExtension() }
        } message: {
            Text("Mac Monitor and macmonitor stop seeing events until you install it again.")
        }
    }
}


/// A row with a title, what it does, and its button at the trailing edge.
struct ActionRow<Control: View>: View {
    let title: String
    let detail: String
    @ViewBuilder let control: Control

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).fontWeight(.semibold)
                Text(detail).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            control
        }
        .padding(.vertical, 12)
        .padding(.horizontal, 14)
    }
}
