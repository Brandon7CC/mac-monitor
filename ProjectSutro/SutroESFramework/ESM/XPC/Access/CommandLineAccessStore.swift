//
//  CommandLineAccessStore.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation


// MARK: - Command line access store
/// Where the Security Extension keeps ``CommandLineAccess`` (Security Extension context): its own preferences, which
/// it reads and writes as root (`/var/root/Library/Preferences`), so only the Security Extension (or root) changes
/// them. Who may ask it to is the Security Extension's call (`SensorService`), not the store's.
///
/// **Fails closed:** a missing or unreadable value is ``CommandLineAccess/rootOnly``.
///
/// **Managed:** a configuration profile that sets ``key`` decides the level, and Settings can't change it.
public final class CommandLineAccessStore: @unchecked Sendable {
    /// The preference's key.
    public static let key = "CommandLineAccess"

    /// The Security Extension's preferences, or a test's suite.
    private let defaults: UserDefaults

    /// - Parameter defaults: Where the level is kept.
    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    /// Who may use `macmonitor` without `sudo` now.
    public var access: CommandLineAccess {
        defaults.string(forKey: Self.key).flatMap(CommandLineAccess.init(rawValue:)) ?? .rootOnly
    }

    /// Change the level.
    ///
    /// - Parameter access: The new level.
    /// - Returns: ``CommandLineAccessChange/done``, or why nothing changed.
    public func change(to access: CommandLineAccess) -> CommandLineAccessChange {
        guard !defaults.objectIsForced(forKey: Self.key) else { return .managed }
        defaults.set(access.rawValue, forKey: Self.key)
        return self.access == access ? .done : .unavailable
    }
}


// MARK: - Change outcome
/// What a request to change ``CommandLineAccess`` did, as it travels back to Mac Monitor.
public enum CommandLineAccessChange: Int, Error, CaseIterable, Sendable {
    /// The level was changed.
    case done = 0
    /// Another Mac Monitor owns the event stream.
    case streamOwned = 1
    /// Not a level this Security Extension knows.
    case invalid = 2
    /// A configuration profile sets the level.
    case managed = 3
    /// The Security Extension couldn't be reached, or couldn't keep the change.
    case unavailable = 4

    /// What to tell the user.
    ///
    /// - Returns: A sentence, or `nil` for done.
    public var message: String? {
        switch self {
        case .done: return nil
        case .streamOwned:
            return "Another Mac Monitor owns the event stream, so only it can change this. Nothing changed."
        case .invalid: return "The Security Extension is older than Mac Monitor. Nothing changed."
        case .managed: return "A configuration profile decides who can use macmonitor without sudo."
        case .unavailable: return "Mac Monitor couldn't reach its Security Extension, so nothing changed."
        }
    }
}
