//
//  IndicatorAlertStatus.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Why notifications may not show
/// The one line Settings > Indicators shows under its notification switches when they may not show: the first of
/// these that applies. The switches themselves are never turned off for it.
public enum IndicatorAlertStatus: Equatable, Sendable {
    /// macOS won't take notifications from this build, such as an unsigned one.
    case notAllowed
    /// The user turned Mac Monitor's notifications off in System Settings.
    case denied
    /// They're on, but only go to Notification Center: no banner or alert.
    case quiet
    /// macOS hasn't asked the user yet, or the user dismissed its prompt without answering: nothing posts until they
    /// allow it.
    case notAsked
    /// The Security Extension is older than 3.1, so events carry no verdicts.
    case needsSecurityExtension
    /// Another Mac Monitor owns the event stream, so its user gets the events.
    case streamOwned

    /// What macOS says of this app's notifications, as `UNNotificationSettings` gives it.
    public enum Authorization: Equatable, Sendable {
        /// Not asked yet.
        case notDetermined
        /// Off in System Settings.
        case denied
        /// On, and shown as banners or alerts.
        case authorized
        /// On, but only in Notification Center.
        case quiet
        /// macOS refused to ask, or to post: `UNError.notificationsNotAllowed`.
        case notAllowed
    }

    /// - Parameters:
    ///   - authorization: What macOS says of this app's notifications.
    ///   - connection: How the indicator engine last heard from the Security Extension.
    ///   - streamOwned: Does another Mac Monitor own the event stream?
    /// - Returns: The first status that applies, or `nil` when notifications can show.
    public static func current(authorization: Authorization, connection: IndicatorEngine.Connection,
                               streamOwned: Bool) -> IndicatorAlertStatus? {
        switch authorization {
        case .notAllowed: return .notAllowed
        case .denied: return .denied
        case .quiet: return .quiet
        case .notDetermined: return .notAsked
        case .authorized: break
        }
        if connection == .unavailable { return .needsSecurityExtension }
        return streamOwned ? .streamOwned : nil
    }

    /// What Settings says.
    public var message: String {
        switch self {
        case .notAllowed: "macOS doesn't allow notifications from this build of Mac Monitor."
        case .denied: "Notifications for Mac Monitor are off in System Settings."
        case .quiet:
            "Mac Monitor's notifications only go to Notification Center. Choose Banners or Alerts in System Settings."
        case .notAsked: "Mac Monitor hasn't been allowed to notify yet."
        case .needsSecurityExtension: "Notifications need the 3.1 Security Extension."
        case .streamOwned: "Another Mac Monitor owns the event stream, so notifications go to its user."
        }
    }

    /// Does Settings offer to open System Settings' Notifications pane for it?
    public var opensNotificationSettings: Bool { self == .denied || self == .quiet }

    /// Does Settings offer to ask macOS for permission for it? Only the user's click asks, never Mac Monitor at launch.
    public var requestsAuthorization: Bool { self == .notAsked }

    /// - Parameter bundleIdentifier: The app's bundle identifier.
    /// - Returns: System Settings' Notifications pane for the app.
    public static func notificationSettingsURL(for bundleIdentifier: String) -> URL? {
        URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=" + bundleIdentifier)
    }
}
