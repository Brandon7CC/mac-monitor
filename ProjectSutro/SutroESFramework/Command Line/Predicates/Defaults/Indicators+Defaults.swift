//
//  Indicators+Defaults.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation


// MARK: - Defaults
public extension Indicator {
    /// The indicators Mac Monitor ships, each with an identity of its own, so Restore Defaults puts back the same ones.
    /// They're the indicators of the signed pack this build links in (``LinkedIndicatorPack``), which the indicators
    /// repository builds and tests.
    ///
    /// Each names its own severity, tactic and technique, which the pack's authors chose with its rule.
    static let defaults: [Indicator] = LinkedIndicatorPack.pack.indicators

    /// The identities never used again, as the linked pack's header lists them: the defaults Mac Monitor 3.1 stopped
    /// shipping (Not quarantined, osascript and Non-Apple as root), and any retired since. A saved reference to one
    /// is dropped, where one to an indicator that's only away is kept.
    static let retiredDefaults = Set(LinkedIndicatorPack.pack.pack.retired)

    /// The New executable indicator's predicate: an exec of an executable created less than
    /// ``ESProcessExecEvent/newExecutableAge`` before it ran. The indicator, its mark, Event Facts' clock and Event
    /// Search's starter search all use it, so they select the same execs.
    static let newExecutablePredicate = shippedPredicate(9)
}


// MARK: - Shipped identities
extension Indicator {
    /// - Parameter number: A default's number.
    /// - Returns: The default. The numbers the built-in marks and the app name are ones the file lists, which a test
    ///   pins.
    static func shipped(_ number: Int) -> Indicator {
        defaults.first { $0.id == uuid(number) }!
    }

    /// - Parameter number: A default's number.
    /// - Returns: The default's predicate. The defaults the built-in marks and the app name are rules on one event,
    ///   which a test pins.
    static func shippedPredicate(_ number: Int) -> String {
        shipped(number).predicate!
    }
}
