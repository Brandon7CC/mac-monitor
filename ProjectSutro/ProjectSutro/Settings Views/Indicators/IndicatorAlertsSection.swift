//
//  IndicatorAlertsSection.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/8/26.
//

import SwiftUI
import SutroESFramework


// MARK: - Settings > Indicators > Notifications
/// This user's indicator notifications, as the popover Settings > Indicators' bell button opens: a switch for High
/// and one for Medium, when they come, the one reason they may not show, if any (``IndicatorAlertStatus``), and how
/// many indicators this user said not to notify for, with Reset.
struct IndicatorAlertsSection: View {
    @ObservedObject private var center = IndicatorAlertCenter.shared
    @ObservedObject private var store = IndicatorStore.shared
    @EnvironmentObject private var manager: EndpointSecurityManager

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Notify me when an indicator matches").font(.headline)
            VStack(spacing: 8) {
                row("High severity", detail: "A strong sign of malicious activity.", symbol: "bell.badge.fill",
                    severity: .high, isOn: $center.high)
                Divider()
                row("Medium severity", detail: "Suspicious behavior that has benign uses.", symbol: "bell.fill",
                    severity: .medium, isOn: $center.medium)
            }
            Text("While Mac Monitor records. Each indicator notifies at once, then sums up its later matches, less "
                 + "often while it keeps matching. Traces you open never notify. With Drop platform binaries on, "
                 + "events from Apple's own tools don't notify.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let status {
                VStack(alignment: .leading, spacing: 6) {
                    Label(status.message, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                    if status.opensNotificationSettings {
                        Button("Open Notification Settings…") { center.openNotificationSettings() }
                    }
                    if status.requestsAuthorization {
                        Button("Allow Notifications…") { center.requestAuthorization() }
                    }
                }
            }
            if silencedCount > 0 {
                HStack(spacing: 8) {
                    Label(silencedSummary, systemImage: "bell.slash").font(.callout).foregroundStyle(.secondary)
                    Spacer()
                    Button("Reset") { center.resetSilenced() }
                }
            }
        }
        .padding(16)
        .frame(width: 360)
        .onAppear { center.refreshAuthorization() }
    }

    /// - Parameters:
    ///   - title: The severity's name.
    ///   - detail: What a match of that severity means.
    ///   - symbol: The row's SF Symbol.
    ///   - severity: The severity, whose color the tile takes.
    ///   - isOn: Whether its matches notify.
    /// - Returns: The severity's row: its tile, name and meaning, then its switch.
    private func row(_ title: String, detail: String, symbol: String, severity: IndicatorSeverity,
                     isOn: Binding<Bool>) -> some View {
        HStack(spacing: 10) {
            SettingsIconLabel(title, detail: detail, symbol: symbol, tint: severity.tint)
            Spacer(minLength: 8)
            Toggle("Notify me for \(title)", isOn: isOn).labelsHidden().toggleStyle(.switch).controlSize(.small)
        }
    }

    /// Why notifications may not show, while a switch is on.
    private var status: IndicatorAlertStatus? {
        guard center.high || center.medium else { return nil }
        return IndicatorAlertStatus.current(authorization: center.authorization, connection: store.engine.connection,
                                            streamOwned: manager.connectionResult == .streamOwned)
    }

    /// How many of the Mac's indicators this user silenced, leaving out those the set no longer has.
    private var silencedCount: Int {
        center.settings.silencedCount(among: store.indicators)
    }

    /// Such as "2 indicators don't notify you".
    private var silencedSummary: String {
        let count = silencedCount
        return count == 1 ? "1 indicator doesn't notify you" : "\(count) indicators don't notify you"
    }
}
