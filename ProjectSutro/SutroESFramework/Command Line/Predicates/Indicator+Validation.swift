//
//  Indicator+Validation.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Limits
public extension Indicator {
    /// How long an indicator's fields may be. An indicator past one doesn't decode, and the Security Extension refuses
    /// it. They're kept in code, not the telemetry schema, whose validator has no lengths or counts.
    enum Limits {
        /// The most Unicode scalars in a name. Scalars, not characters, so combining marks can't stretch one
        /// character past any size: a name ships in every record that matches.
        public static let name = 128
        /// The most UTF-8 bytes in a description: 2 KiB.
        public static let descriptionBytes = 2_048
        /// The most Unicode scalars in an SF Symbol's name.
        public static let symbol = 64
        /// What a technique looks like: `T1059`, or a sub-technique, `T1059.002`.
        public static let technique = #"^T\d{4}(\.\d{3})?$"#
    }

    /// Which field is past its limit, and how, or `nil` when every one is within its own.
    var limitProblem: String? {
        if name.unicodeScalars.count > Limits.name { return "Its name is longer than \(Limits.name) characters." }
        if description.utf8.count > Limits.descriptionBytes {
            return "Its description is longer than \(Limits.descriptionBytes / 1_024) KiB."
        }
        if symbol.unicodeScalars.count > Limits.symbol {
            return "Its symbol's name is longer than \(Limits.symbol) characters."
        }
        if let technique, !Self.isTechnique(technique) {
            return "Its technique '\(technique)' isn't an ATT&CK technique, such as T1059 or T1059.002."
        }
        return nil
    }

    /// Whether a string is an ATT&CK technique, as ``Limits/technique`` describes one.
    ///
    /// - Parameter technique: The technique to check.
    /// - Returns: `true` for `T1059` or `T1059.002`, `false` otherwise.
    static func isTechnique(_ technique: String) -> Bool {
        technique.range(of: Limits.technique, options: .regularExpression) != nil
    }

    /// Why the Security Extension can't run its predicate, or `nil` when it can (``IndicatorCompiler``). It's set
    /// whenever ``problem`` is, and also for a predicate Mac Monitor can match on a record but the Security Extension
    /// can't on an event, such as one that names no event type.
    var sensorProblem: String? {
        IndicatorCompiler.problem(with: predicate)?.description
    }
}
