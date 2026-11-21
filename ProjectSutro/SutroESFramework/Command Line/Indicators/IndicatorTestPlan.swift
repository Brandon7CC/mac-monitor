//
//  IndicatorTestPlan.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Test plans
/// The cases `macmonitor indicators test` replays, as the indicators repository's `tools/mmi test` writes them: each
/// case names an indicator in the pack, a file of recorded Mac Monitor events and what the indicator must do on them,
/// and the benign corpus lists longer captures of ordinary use, each with the hits an override allows.
///
/// ```json
/// { "cases": [ { "id": "6D4D0F1D-...", "name": "xattr -d removes the quarantine attribute",
///                "events": "indicators/defense_impairment/quarantine-attribute-removed/events/xattr-d.jsonl",
///                "expect": "match", "count": 1 } ],
///   "corpus": [ { "events": "corpus/benign/xcode-build.jsonl", "allowed_hits": { "6D4D0F1D-...": 2 } } ] }
/// ```
///
/// Paths are relative to the folder the command runs in, the repository's root.
public struct IndicatorTestPlan: Decodable, Equatable {
    /// What a case's indicator must do on its events.
    public enum Expectation: String, Decodable, Sendable {
        /// Match: at least one record, or exactly `count`, and every one of `records`.
        case match
        /// Match no record.
        case none
    }

    /// One case: an indicator, a file of events, and what it must do on them.
    public struct Case: Decodable, Equatable {
        /// The indicator's identity in the pack.
        public let id: UUID
        /// What the case shows, as a sentence.
        public let name: String
        /// The JSONL file of recorded events, relative to the repository's root.
        public let events: String
        /// What the indicator must do on them.
        public let expect: Expectation
        /// With ``Expectation/match``, exactly how many records must match, or `nil` for at least one.
        public let count: Int?
        /// With ``Expectation/match``, the lines, from 1, whose records must match, or `nil` for any. For a sequence,
        /// the lines that complete it.
        public let records: [Int]?
    }

    /// One benign corpus capture: ordinary use no indicator should hit, past what an override allows.
    public struct Capture: Decodable, Equatable {
        /// The JSONL file of recorded events, relative to the repository's root.
        public let events: String
        /// The hits an override allows, by indicator. One not listed is allowed none.
        public let allowedHits: [UUID: Int]

        private enum CodingKeys: String, CodingKey {
            case events
            case allowedHits = "allowed_hits"
        }

        /// Decode a capture. Its allowed hits are keyed by identity, as JSON keys.
        ///
        /// - Parameter decoder: The decoder.
        /// - Throws: When a key is missing or isn't what it should be, or an allowed hit's key isn't an identity.
        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            events = try container.decode(String.self, forKey: .events)
            let allowed = try container.decodeIfPresent([String: Int].self, forKey: .allowedHits) ?? [:]
            allowedHits = try Dictionary(uniqueKeysWithValues: allowed.map { key, hits in
                guard let id = UUID(uuidString: key) else {
                    throw DecodingError.dataCorruptedError(forKey: .allowedHits, in: container,
                                                           debugDescription: "'\(key)' isn't an indicator's ID.")
                }
                return (id, hits)
            })
        }
    }

    /// The cases, in the order to replay them.
    public let cases: [Case]
    /// The benign corpus captures that have been downloaded.
    public let corpus: [Capture]

    private enum CodingKeys: String, CodingKey {
        case cases, corpus
    }

    /// Decode a plan. One without `corpus` has none.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: When `cases` is missing, or a key isn't what it should be.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        cases = try container.decode([Case].self, forKey: .cases)
        corpus = try container.decodeIfPresent([Capture].self, forKey: .corpus) ?? []
    }
}
