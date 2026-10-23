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
        SettingsForm(pane: .securityExtension) {
            Section {
                ForEach(systemExtensionManager.requirements.rows) { row in
                    RequirementRow(row: row, padded: false)
                }
            } footer: {
                HStack {
                    Spacer()
                    Button("Check Again") { systemExtensionManager.refreshRequirements() }
                }
            }
            Section {
                LabeledContent {
                    Button("Reinstall") { systemExtensionManager.activateSystemExtension() }
                } label: {
                    SettingsLabel("Reinstall", detail: "Asks macOS to activate this copy's Security Extension again.")
                }
                LabeledContent {
                    Button("Uninstall…", role: .destructive) { confirmsUninstall = true }
                } label: {
                    SettingsLabel("Uninstall",
                                  detail: "Stops all monitoring. macOS asks for an administrator's password.")
                }
            }
        }
        .onAppear { systemExtensionManager.refreshRequirements() }
        .confirmationDialog("Uninstall the Security Extension?", isPresented: $confirmsUninstall) {
            Button("Uninstall", role: .destructive) { systemExtensionManager.uninstallSystemExtension() }
        } message: {
            Text("Mac Monitor and macmonitor stop seeing events until you install it again.")
        }
    }
}


/// A row's label: its name, and what it does underneath.
struct SettingsLabel: View {
    let title: String
    let detail: String

    /// - Parameters:
    ///   - title: The row's name.
    ///   - detail: What it does.
    init(_ title: String, detail: String) {
        self.title = title
        self.detail = detail
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
            Text(detail).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }
}
