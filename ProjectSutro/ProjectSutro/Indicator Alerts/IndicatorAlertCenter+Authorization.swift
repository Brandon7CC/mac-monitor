//
//  IndicatorAlertCenter+Authorization.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/8/26.
//

import AppKit
import UserNotifications
import SutroESFramework


// MARK: - Permission
extension IndicatorAlertCenter {
    /// Read what macOS says of Mac Monitor's notifications: at launch, when Settings shows them, and whenever Mac
    /// Monitor becomes active, as after the user changed them in System Settings. Never asks.
    func refreshAuthorization() {
        UNUserNotificationCenter.current().getNotificationSettings { [weak self] settings in
            let read = Self.authorization(of: settings)
            Task { @MainActor in
                /// macOS refusing this build stays known until it's asked again or says more.
                guard let self, self.authorization != .notAllowed || read != .notDetermined else { return }
                self.authorization = read
            }
        }
    }

    /// Ask macOS to let Mac Monitor notify, with sound: only when a switch is turned on and it hasn't been asked, or
    /// when the user clicks Allow Notifications in Settings. Not provisionally, which delivers quietly: wrong for a
    /// detection.
    func requestAuthorization() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { [weak self] _, error in
            if let error {
                Self.logger.error("Notification permission failed: \(error.localizedDescription, privacy: .public)")
            }
            Task { @MainActor in
                if error != nil { self?.authorization = .notAllowed } else { self?.refreshAuthorization() }
            }
        }
    }

    /// Open System Settings' Notifications pane for Mac Monitor.
    func openNotificationSettings() {
        guard let url = IndicatorAlertStatus.notificationSettingsURL(for: Bundle.main.bundleIdentifier ?? "") else {
            return
        }
        NSWorkspace.shared.open(url)
    }

    /// Register the categories, with their actions and the placeholder a locked screen shows instead of the text.
    func registerCategories() {
        let showAll = UNNotificationAction(identifier: IndicatorAlertInfo.showAllAction, title: "Show All Matches",
                                           options: [.foreground])
        let dontNotify = UNNotificationAction(identifier: IndicatorAlertInfo.dontNotifyAction,
                                              title: "Don't Notify for This Indicator", options: [])
        let categories = [(IndicatorAlertContent.category, [showAll, dontNotify]),
                          (IndicatorAlertContent.overflowCategory, [showAll])].map { identifier, actions in
            UNNotificationCategory(identifier: identifier, actions: actions, intentIdentifiers: [],
                                   hiddenPreviewsBodyPlaceholder: "Indicator match", options: [])
        }
        UNUserNotificationCenter.current().setNotificationCategories(Set(categories))
    }

    /// - Parameter settings: Mac Monitor's notification settings.
    /// - Returns: What they mean for posting.
    nonisolated private static func authorization(of settings: UNNotificationSettings)
        -> IndicatorAlertStatus.Authorization {
        switch settings.authorizationStatus {
        case .notDetermined: return .notDetermined
        case .denied: return .denied
        case .authorized, .provisional, .ephemeral:
            return settings.alertSetting == .disabled || settings.alertStyle == .none ? .quiet : .authorized
        @unknown default: return .denied
        }
    }
}
