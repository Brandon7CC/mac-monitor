//
//  UserSettingsView.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 5/18/23.
//

import SwiftUI
import SutroESFramework


// MARK: - Settings > General
/// Settings > General: Mac Monitor's updates, the warnings before quitting and clearing, dark mode, what the Security
/// Extension adds to events, and which parents Event Facts' process tree follows.
struct GeneralSettingsView: View {
    @EnvironmentObject var userPrefs: UserPrefs
    @EnvironmentObject var systemExtensionManager: EndpointSecurityManager
    @StateObject private var releaseNotes = ReleaseNotes()
    @State private var confirmsReset = false
    @State private var showsReleaseNotes = false
    /// The last Check Now's state, for the version row.
    @State private var isChecking = false
    @State private var lastCheck: UpdateCheck?
    /// The check to show over Settings, as Mac Monitor > Check for Updates shows it.
    @State private var shownCheck: UpdateCheck?
    /// Why the Security Extension last refused to turn each enrichment switch on or off, by the switch's first name,
    /// since Settings opened or the handshake last changed.
    @State private var refusals: [String: String] = [:]
    /// The two flow events, which Record network flows turns on and off together.
    private static let flowEvents = MacMonitorEvent.allCases.map(\.name)
    /// Why Record network flows and Record URL paths are refused while capture runs.
    private static let flowsUnreadable = "Network flows can't be read on this Mac."

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
                /// Not in 3.2: indicator pack updates (`SavedIndicatorSet+Updates.swift`). The rows are done, and
                /// wait for a later release.
                // IndicatorPackSettings()
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
            Section("Enrichment") {
                Toggle(isOn: subscriptions([YaraScan.subscriptionName])) {
                    SettingsIconLabel("Scan written files with XProtect's rules",
                                      detail: refusals[YaraScan.subscriptionName]
                                        ?? "Mach-O files and scripts when they're written, and scripts when they run.",
                                      symbol: "xmark.shield", tint: .red)
                }
                .disabled(!systemExtensionManager.hasEventSubscriptions)
                let recordsFlows = subscriptions(Self.flowEvents, onThisMac: Self.flowsUnreadable)
                Toggle(isOn: recordsFlows) {
                    SettingsIconLabel("Record network flows",
                                      detail: refusals[Self.flowEvents[0]]
                                        ?? "The connections each process opens and closes, with their hosts and URLs.",
                                      symbol: "network", tint: .blue)
                }
                .disabled(!systemExtensionManager.hasEventSubscriptions)
                Toggle(isOn: subscriptions([NetworkFlowEvent.urlPathsSubscriptionName],
                                           onThisMac: Self.flowsUnreadable)) {
                    SettingsIconLabel("Record URL paths",
                                      detail: refusals[NetworkFlowEvent.urlPathsSubscriptionName]
                                        ?? "A flow's URL keeps its path. A query is never recorded.",
                                      symbol: "link", tint: .teal)
                }
                .disabled(!systemExtensionManager.hasEventSubscriptions || !recordsFlows.wrappedValue)
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
        .updateCheckResult($shownCheck)
        .onAppear { systemExtensionManager.requestEventSubscriptions() }
        /// A refusal under one handshake says nothing of the next.
        .onChange(of: systemExtensionManager.connectionResult) { _ in refusals = [:] }
    }

    /// An enrichment switch, as the Security Extension last said: scanning written files with Apple's XProtect rules
    /// (``YaraScan/subscriptionName``), recording network flows (their two events), or keeping URL paths
    /// (``NetworkFlowEvent/urlPathsSubscriptionName``). It's on while every name is subscribed. A change the
    /// Security Extension refuses, on or off, leaves the switch as it was, and ``refusals`` says why.
    ///
    /// - Parameters:
    ///   - names: The subscription names it turns on and off together.
    ///   - onThisMac: What stops it while capture runs, or `nil` for a switch only a stopping capture refuses.
    /// - Returns: The switch's binding.
    private func subscriptions(_ names: [String], onThisMac: String? = nil) -> Binding<Bool> {
        Binding {
            names.allSatisfy(systemExtensionManager.monitoredEventStrings.contains)
        } set: { enabled in
            refusals[names[0]] = nil
            for name in names {
                systemExtensionManager.setSubscription(name, enabled: enabled) { reply in
                    if reply != true {
                        refusals[names[0]] = systemExtensionManager.connectionResult
                            .refusal(answered: reply != nil, onThisMac: onThisMac)
                    }
                    systemExtensionManager.requestEventSubscriptions()
                }
            }
        }
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

    /// Asks the Security Extension for a newer release, then shows the update sheet or the alert that says there's none.
    private func checkNow() {
        (isChecking, lastCheck) = (true, nil)
        systemExtensionManager.checkForUpdates { check in
            (isChecking, lastCheck, shownCheck) = (false, check, check)
        }
    }
}
