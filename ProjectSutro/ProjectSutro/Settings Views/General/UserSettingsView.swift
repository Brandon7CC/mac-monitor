//
//  UserSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 5/18/23.
//

import SwiftUI
import SutroESFramework


// MARK: - Settings ▸ General
/// Settings ▸ General: updates, the warnings before quitting and clearing, dark mode, and which parents Event Facts'
/// process tree follows.
struct GeneralSettingsView: View {
    @EnvironmentObject var userPrefs: UserPrefs
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @StateObject private var releaseNotes = ReleaseNotes()
    @State private var confirmsReset = false
    @State private var showsReleaseNotes = false
    /// The last Check Now's state. The update sheet opens over Settings when one is found.
    @State private var isChecking = false
    @State private var lastCheck: UpdateCheck?
    @State private var update: UpdateDetails?

    var body: some View {
        SettingsForm(pane: .general) {
            Section("Updates") {
                LabeledContent {
                    HStack(spacing: 12) {
                        Link("Releases", destination: ReleaseNotes.releasesPage)
                            .help("Every version of Mac Monitor, on GitHub")
                        Button("Release Notes…") { showsReleaseNotes = true }
                        Button("Check Now", action: checkNow)
                            .disabled(isChecking || !EndpointSecurityManager.supportsUpdates)
                    }
                } label: {
                    SettingsIconLabel("Mac Monitor \(ReleaseNotes.version) (\(ReleaseNotes.build))",
                                      detail: versionDetail, symbol: "shippingbox.fill", tint: .green)
                }
                Toggle(isOn: userPrefs.$autoUpdates) {
                    SettingsIconLabel("Check for updates", detail: "Mac Monitor looks for a new release when it opens.",
                                      symbol: "arrow.down.circle.fill", tint: .blue)
                }
                .disabled(!EndpointSecurityManager.supportsUpdates)
                .help(EndpointSecurityManager.supportsUpdates ? "" : "Community builds don't update themselves.")
            }
            Section {
                Toggle(isOn: userPrefs.$lifecycleWarnBeforeQuit) {
                    SettingsIconLabel("Warn before quitting", detail: "Ask first, in case ⌘Q was a slip.",
                                      symbol: "power", tint: .red)
                }
                Toggle(isOn: userPrefs.$lifecycleWarnBeforeClear) {
                    SettingsIconLabel("Warn before clearing events",
                                      detail: "Ask before Clear removes what's recorded.",
                                      symbol: "trash.fill", tint: .orange)
                }
                Toggle(isOn: userPrefs.$forcedDarkMode) {
                    SettingsIconLabel("Always use dark mode", detail: "The View menu turns it on and off too.",
                                      symbol: "moon.fill", tint: .indigo)
                }
            }
            Section("Process tree") {
                ProcessTreePrefsView()
            }
            Section {
                LabeledContent {
                    Button("Reset…") { confirmsReset = true }
                } label: {
                    SettingsIconLabel("Reset preferences",
                                      detail: "The warnings and the event tables' menus go back to how Mac "
                                        + "Monitor ships.",
                                      symbol: "arrow.counterclockwise", tint: .gray)
                }
            }
        }
        .confirmationDialog("Reset preferences?", isPresented: $confirmsReset) {
            Button("Reset", role: .destructive) { userPrefs.resetAllPreferences() }
        } message: {
            Text("The warnings and the event tables' menus go back to how Mac Monitor ships.")
        }
        .sheet(isPresented: $showsReleaseNotes) {
            ReleaseNotesSheet(notes: releaseNotes)
        }
        .sheet(item: $update) { UpdateAvailableSheet(updateDetails: $0) }
    }

    /// The version row's second line. It says how the last Check Now went.
    private var versionDetail: String {
        if !EndpointSecurityManager.supportsUpdates { return "Community builds don't update themselves." }
        if isChecking { return "Checking for updates…" }
        switch lastCheck {
        case .upToDate: return "Mac Monitor is up to date."
        case .failed: return "No internet connection."
        case .newer, nil: return "What's new, and every release, are on GitHub."
        }
    }

    /// Asks the Security Extension for a newer release. A newer one opens the update sheet.
    private func checkNow() {
        (isChecking, lastCheck) = (true, nil)
        systemExtensionManager.checkForUpdates { check in
            (isChecking, lastCheck) = (false, check)
            if case .newer(let details) = check { update = details }
        }
    }
}
