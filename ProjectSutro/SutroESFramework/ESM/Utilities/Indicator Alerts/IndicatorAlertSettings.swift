//
//  IndicatorAlertSettings.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Notification settings
/// Which indicator matches notify this user: a switch for High and one for Medium, never Low, and the indicators this
/// user said not to notify for (Don't Notify). Both switches are off until the user turns one on.
///
/// They're this user's, in their user defaults, under keys of their own: not in the Mac's indicator set, which is
/// every user's, nor in ``IndicatorOverlay``, whose lenient decode would drop every view switch on an older read of a
/// key it doesn't know.
public struct IndicatorAlertSettings: Equatable, Sendable {
    /// The user default for the High switch.
    public static let highKey = "indicators.alerts.high"
    /// The user default for the Medium switch.
    public static let mediumKey = "indicators.alerts.medium"
    /// The user default for the silenced indicators: an array of UUID strings.
    public static let silencedKey = "indicators.alerts.silenced"

    /// Do High matches notify?
    public var high: Bool
    /// Do Medium matches notify?
    public var medium: Bool
    /// The indicators that never notify this user, by identity.
    public var silenced: Set<UUID>

    /// - Parameters:
    ///   - high: Do High matches notify?
    ///   - medium: Do Medium matches notify?
    ///   - silenced: The indicators that never notify.
    public init(high: Bool = false, medium: Bool = false, silenced: Set<UUID> = []) {
        self.high = high
        self.medium = medium
        self.silenced = silenced
    }

    /// The settings a user saved, leniently: a missing key is its default, and a silenced entry that isn't a UUID is
    /// dropped.
    ///
    /// - Parameter defaults: The user's defaults.
    public init(defaults: UserDefaults) {
        let entries = defaults.array(forKey: Self.silencedKey) ?? []
        self.init(high: defaults.bool(forKey: Self.highKey), medium: defaults.bool(forKey: Self.mediumKey),
                  silenced: Set(entries.compactMap { ($0 as? String).flatMap(UUID.init(uuidString:)) }))
    }

    /// Keep them in a user's defaults, under their own keys only.
    ///
    /// - Parameter defaults: The user's defaults.
    public func save(to defaults: UserDefaults) {
        defaults.set(high, forKey: Self.highKey)
        defaults.set(medium, forKey: Self.mediumKey)
        defaults.set(silenced.map(\.uuidString).sorted(), forKey: Self.silencedKey)
    }

    /// - Parameter severity: A match's severity.
    /// - Returns: Do matches of it notify? Low never does.
    public func notifies(for severity: IndicatorSeverity) -> Bool {
        switch severity {
        case .high: high
        case .medium: medium
        case .low: false
        }
    }

    /// Is every switch off, so nothing notifies?
    public var isOff: Bool { !high && !medium }

    /// How many of the Mac's indicators this user silenced. An identity the set no longer has, such as a shipped
    /// indicator a later build dropped or one deleted since, is kept but not counted: it can't notify.
    ///
    /// - Parameter indicators: The Mac's indicators.
    /// - Returns: The count.
    public func silencedCount(among indicators: [Indicator]) -> Int {
        silenced.isEmpty ? 0 : indicators.reduce(0) { $0 + (silenced.contains($1.id) ? 1 : 0) }
    }
}
