//
//  CanonicalSpellings.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Canonically equal spellings
/// One path spelled two ways that Swift's `String` takes as equal and a predicate's `==`, `!=` and `IN` don't: NFC
/// "é", and NFD "e" with a combining acute. Indicators that compare an exec's target path with each must keep their
/// own programs and verdicts, wherever they're shared by their predicate's text.
enum CanonicalSpellings {
    /// The path in NFC.
    static let nfc = "/tmp/caf\u{E9}"
    /// The path in NFD.
    static let nfd = "/tmp/cafe\u{301}"

    /// A pair of indicators, one comparing with each spelling, and the one an exec whose path is ``nfd`` matches.
    struct Pair {
        /// The comparison, `%@` standing for the constant.
        let format: String
        /// The indicator comparing with ``nfc``.
        let composed: Indicator
        /// The indicator comparing with ``nfd``.
        let decomposed: Indicator
        /// The identity of the one that matches.
        let hit: UUID
    }

    /// `==`, `IN` and `!=`, each as a pair.
    static var pairs: [Pair] {
        [("target_path == %@", true), ("target_path IN {%@}", true), ("target_path != %@", false)]
            .map { format, decomposedHits in
                let composed = indicator(format, nfc), decomposed = indicator(format, nfd)
                return Pair(format: format, composed: composed, decomposed: decomposed,
                            hit: decomposedHits ? decomposed.id : composed.id)
            }
    }

    /// - Parameters:
    ///   - format: A comparison, `%@` standing for the constant.
    ///   - constant: The path, in one spelling.
    /// - Returns: An indicator of someone's own on execs that makes it.
    private static func indicator(_ format: String, _ constant: String) -> Indicator {
        let comparison = format.replacingOccurrences(of: "%@", with: "\"\(constant)\"")
        return Indicator(name: "Test", description: "", symbol: "star", color: .blue,
                         predicate: #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" AND "# + comparison)
    }
}
