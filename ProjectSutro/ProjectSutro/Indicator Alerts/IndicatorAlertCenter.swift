//
//  IndicatorAlertCenter.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/8/26.
//

import SwiftUI
import Combine
import UserNotifications
import OSLog
import os
import SutroESFramework


// MARK: - Indicator notifications
/// Posts macOS notifications for this user's High and Medium indicator matches while Mac Monitor records, and answers
/// their clicks (``IndicatorAlertCenter+Responses``). The rules are the framework's: which hits notify
/// (``IndicatorAlertPolicy``), how often (``IndicatorAlertScheduler``), and what they say (``IndicatorAlertContent``).
/// Here are the switches, which are this user's (``IndicatorAlertSettings``), the permission
/// (``IndicatorAlertCenter+Authorization``), and `UNUserNotificationCenter`.
///
/// Nothing notifies until a main window ``attach(_:search:openWindow:)``es it, and nothing is asked of macOS until a
/// switch is turned on. The switches are never turned off by Mac Monitor itself.
@MainActor
final class IndicatorAlertCenter: NSObject, ObservableObject {
    static let shared = IndicatorAlertCenter()

    /// Do High matches notify?
    @Published var high: Bool { didSet { switched(on: high && !oldValue) } }
    /// Do Medium matches notify?
    @Published var medium: Bool { didSet { switched(on: medium && !oldValue) } }
    /// The indicators that never notify this user.
    @Published private(set) var silenced: Set<UUID>
    /// What macOS says of Mac Monitor's notifications, as last read.
    @Published var authorization: IndicatorAlertStatus.Authorization = .notDetermined {
        didSet { canPost.withLock { [authorization] in $0 = [.authorized, .quiet].contains(authorization) } }
    }

    /// Where the switches are kept.
    let defaults: UserDefaults
    /// Coalesces matches, and posts on its queue.
    private let scheduler: IndicatorAlertScheduler
    /// May notifications be posted? Read on the scheduler's queue.
    private let canPost: OSAllocatedUnfairLock<Bool>
    /// The connection whose tap hands over matches, once attached.
    private(set) weak var manager: EndpointSecurityManager?
    /// The main window's search, for a click that shows matches.
    private(set) weak var search: EventSearchController?
    /// Opens Event Facts and main windows, once attached.
    private(set) var openWindow: OpenWindowAction?
    /// The indicators known to be off, from the Mac's set.
    private var disabled: Set<UUID> = []
    /// A click that came before ``attach(_:search:openWindow:)``, as when it launched Mac Monitor.
    var heldResponse: (info: IndicatorAlertInfo, action: String)?
    private var observers: [AnyCancellable] = []

    nonisolated static let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "IndicatorAlerts")

    /// - Parameter defaults: Where the switches are kept.
    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        let settings = IndicatorAlertSettings(defaults: defaults)
        (high, medium, silenced) = (settings.high, settings.medium, settings.silenced)
        let canPost = OSAllocatedUnfairLock(initialState: false)
        self.canPost = canPost
        scheduler = IndicatorAlertScheduler { Self.post($0, if: canPost) }
        super.init()
        observers.append(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)
            .sink { [weak self] _ in self?.refreshAuthorization() })
        refreshAuthorization()
    }

    /// This user's settings now.
    var settings: IndicatorAlertSettings {
        IndicatorAlertSettings(high: high, medium: medium, silenced: silenced)
    }

    /// Start notifying for the events Mac Monitor's connection receives, follow the Mac's indicators for those off,
    /// and answer a click that came before.
    ///
    /// - Parameters:
    ///   - manager: Mac Monitor's connection to the Security Extension.
    ///   - search: The main window's search.
    ///   - openWindow: Opens Event Facts and main windows.
    func attach(_ manager: EndpointSecurityManager, search: EventSearchController, openWindow: OpenWindowAction) {
        (self.search, self.openWindow) = (search, openWindow)
        guard self.manager !== manager else { return }
        self.manager = manager
        observers.append(IndicatorStore.shared.$indicators.sink { [weak self] indicators in
            self?.disabled = Set(indicators.filter { !$0.isEnabled }.map(\.id))
            self?.apply()
        })
        if let (info, action) = heldResponse {
            heldResponse = nil
            respond(to: info, action: action)
        }
    }

    /// Notify, or stop notifying, for an indicator.
    ///
    /// - Parameters:
    ///   - id: The indicator's identity.
    ///   - silenced: Should it never notify this user?
    func setSilenced(_ id: UUID, _ silenced: Bool) {
        if silenced { self.silenced.insert(id) } else { self.silenced.remove(id) }
        apply()
    }

    /// Let every indicator notify again.
    func resetSilenced() {
        silenced = []
        apply()
    }

    /// A switch changed: keep it, and ask macOS for permission the first time one turns on.
    ///
    /// - Parameter on: Did a switch turn on?
    private func switched(on: Bool) {
        apply()
        if on && authorization == .notDetermined { requestAuthorization() }
    }

    /// Keep the settings, hand them to the connection's tap, and forget what was gathered for indicators that may
    /// no longer notify.
    private func apply() {
        let (settings, disabled, scheduler) = (settings, disabled, scheduler)
        settings.save(to: defaults)
        manager?.indicatorAlertTap.configure(settings, disabled: disabled) { scheduler.receive($0) }
        scheduler.drop { id, severity in
            !settings.notifies(for: severity) || settings.silenced.contains(id) || disabled.contains(id)
        }
    }

    /// Post notifications, on the scheduler's queue. While macOS doesn't allow them, nothing is built.
    ///
    /// - Parameters:
    ///   - alerts: What the scheduler decided to post.
    ///   - canPost: Does macOS allow them?
    nonisolated private static func post(_ alerts: [IndicatorAlert], if canPost: OSAllocatedUnfairLock<Bool>) {
        guard canPost.withLock({ $0 }) else { return }
        let home = NSHomeDirectory()
        for alert in alerts {
            let content = IndicatorAlertContent(alert, home: home)
            let notification = UNMutableNotificationContent()
            (notification.title, notification.subtitle, notification.body) = (content.title, content.subtitle,
                                                                              content.body)
            notification.threadIdentifier = content.threadIdentifier
            notification.categoryIdentifier = content.info.kind == .overflow ? IndicatorAlertContent.overflowCategory
                : IndicatorAlertContent.category
            notification.userInfo = content.info.userInfo
            notification.sound = content.playsSound ? .default : nil
            notification.interruptionLevel = .active
            let request = UNNotificationRequest(identifier: content.identifier, content: notification, trigger: nil)
            UNUserNotificationCenter.current().add(request) { error in
                guard let error else { return }
                Self.logger.error("Couldn't post a notification: \(error.localizedDescription, privacy: .public)")
                if (error as? UNError)?.code == .notificationsNotAllowed {
                    Task { @MainActor in IndicatorAlertCenter.shared.authorization = .notAllowed }
                }
            }
            Self.logger.info("""
                Posted a \(content.info.kind.rawValue, privacy: .public) notification for \
                \(Self.name(of: alert), privacy: .public): \(alert.count) matches
                """)
        }
    }

    /// - Parameter alert: A notification.
    /// - Returns: Its indicator's name, or how many indicators the overflow holds.
    nonisolated private static func name(of alert: IndicatorAlert) -> String {
        switch alert {
        case .first(let event): event.indicator.name
        case .summary(let summary): summary.latest.indicator.name
        case .overflow(let overflow): "\(overflow.entries.count) indicators"
        }
    }
}
