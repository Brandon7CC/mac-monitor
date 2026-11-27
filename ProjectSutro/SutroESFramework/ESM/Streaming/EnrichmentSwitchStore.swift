//
//  EnrichmentSwitchStore.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/26/26.
//

import Foundation


// MARK: - Enrichment switch store
/// Where the Security Extension keeps Settings > General's enrichment switches (Security Extension context): Record
/// network flows, Scan written files with XProtect's rules, and Record URL paths. Like ``CommandLineAccessStore``, it
/// keeps them in the Security Extension's own preferences, so they're Mac-wide and outlive a restart.
///
/// **On until turned off:** it keeps the names turned off, so a switch with nothing kept is on.
public final class EnrichmentSwitchStore {
    /// The preference's key. Its value is the names turned off.
    static let key = "EnrichmentSwitchesOff"

    /// The subscription names it keeps: the two flow events, ``YaraScan/subscriptionName`` and
    /// ``NetworkFlowEvent/urlPathsSubscriptionName``.
    public static let names = Set(MacMonitorEvent.allCases.map(\.name)
                                  + [YaraScan.subscriptionName, NetworkFlowEvent.urlPathsSubscriptionName])

    /// The Security Extension's preferences, or a test's suite.
    private let defaults: UserDefaults

    /// - Parameter defaults: Where the switches are kept.
    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    /// Is a switch on?
    ///
    /// - Parameter name: One of ``names``.
    /// - Returns: `false` once it's turned off, until it's turned on again.
    func isOn(_ name: String) -> Bool {
        !off.contains(name)
    }

    /// Keep a switch the owner turned on or off. A name that isn't one of ``names`` is left out.
    ///
    /// - Parameters:
    ///   - name: A subscription name.
    ///   - on: Is it on now?
    func save(_ name: String, on: Bool) {
        guard Self.names.contains(name) else { return }
        defaults.set((on ? off.subtracting([name]) : off.union([name])).sorted(), forKey: Self.key)
    }

    /// The names turned off.
    private var off: Set<String> {
        Set(defaults.stringArray(forKey: Self.key) ?? [])
    }
}
