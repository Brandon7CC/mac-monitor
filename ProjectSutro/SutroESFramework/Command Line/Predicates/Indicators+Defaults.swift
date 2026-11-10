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
    /// They're the `indicators` of `Detection/DefaultIndicators.json`, read from this binary (``DefaultIndicators``).
    ///
    /// Each has the severity its evidence earns: high only for an XProtect detection, which is malware macOS itself
    /// found; medium for persistence, injection, payloads, password checks and privacy permissions written around
    /// tccd, which are suspicious but have benign uses (a new executable, an inserted dylib, a login hook, a change to
    /// authentication, a password checked with dscl, a TCC database written); and low for context and what's often
    /// benign (a login, a download tool, a plist, an archive or a compiled script written, quarantine removed, a
    /// keychain opened, a name resolved by unsigned code).
    static let defaults: [Indicator] = DefaultIndicators.file.indicators

    /// The New executable indicator's predicate: an exec of an executable created less than
    /// ``ESProcessExecEvent/newExecutableAge`` before it ran. The indicator, its mark, Event Facts' clock and Event
    /// Search's starter search all use it, so they select the same execs.
    static let newExecutablePredicate = shipped(9).predicate
}


// MARK: - Shipped identities
extension Indicator {
    /// - Parameter number: A default's number.
    /// - Returns: The default. The numbers the built-in marks and the app name are ones the file lists, which a test
    ///   pins.
    static func shipped(_ number: Int) -> Indicator {
        defaults.first { $0.id == uuid(number) }!
    }
}
