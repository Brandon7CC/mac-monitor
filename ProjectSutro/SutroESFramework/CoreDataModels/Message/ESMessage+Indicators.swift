//
//  ESMessage+Indicators.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
import CoreData


// MARK: - Stored verdicts
extension ESMessage {
    /// The event's verdicts as the Security Extension sent them (``Message/indicators``), as JSON: `nil` when nothing
    /// evaluated it, `[]` when it matched none.
    @NSManaged public var indicatorsData: Data?

    /// The JSON of verdicts that matched nothing, stored without encoding: most events'.
    static let noHits = Data("[]".utf8)

    /// - Parameter verdicts: An event's verdicts, or `nil`.
    /// - Returns: What ``indicatorsData`` stores for them: `nil` for none, and `nil` if they can't be encoded.
    static func indicatorsData(of verdicts: IndicatorVerdicts?) -> Data? {
        guard let verdicts else { return nil }
        return verdicts.hits.isEmpty ? noHits : try? JSONEncoder().encode(verdicts)
    }

    /// The event's stored verdicts, or `nil` when it has none or they can't be read.
    public var storedIndicators: [IndicatorHit]? {
        guard let data = indicatorsData else { return nil }
        if data == Self.noHits { return [] }
        return (try? JSONDecoder().decode(IndicatorVerdicts.self, from: data))?.hits
    }

    /// The hits the event's record lists: its stored verdicts, else the indicators' matches now, tagged
    /// ``IndicatorEvaluator/export`` (an Open Trace, an eslogger trace, or an event from an older Security Extension).
    ///
    /// - Parameter indicators: The indicators the encoding lists (``RecordIndicators/current``).
    /// - Returns: The hits, in order, or `nil` for an event with no stored verdicts encoded with
    ///   ``RecordIndicators/stored``: its record has no `indicators` key.
    func recordedIndicators(with indicators: RecordIndicators) -> [IndicatorHit]? {
        storedIndicators ?? indicators.entries(for: self)
    }
}


// MARK: - Stored undetermined indicators
extension ESMessage {
    /// The indicators the Security Extension couldn't rule out for the event (``Message/indicators_undetermined``),
    /// as JSON: `nil` when it decided every one, or nothing evaluated the event.
    @NSManaged public var indicatorsUndeterminedData: Data?

    /// - Parameter undetermined: An event's undetermined indicators, or `nil`.
    /// - Returns: What ``indicatorsUndeterminedData`` stores for them: `nil` for none, and `nil` if they can't be
    ///   encoded.
    static func undeterminedData(of undetermined: UndeterminedIndicators?) -> Data? {
        guard let undetermined, !undetermined.entries.isEmpty else { return nil }
        return try? JSONEncoder().encode(undetermined)
    }

    /// The event's stored undetermined indicators, or `nil` when it has none or they can't be read.
    public var storedUndetermined: [IndicatorUndetermined]? {
        guard let data = indicatorsUndeterminedData else { return nil }
        return (try? JSONDecoder().decode(UndeterminedIndicators.self, from: data))?.entries
    }

    /// The undetermined indicators the event's record lists beside its hits: only those stored with the Security
    /// Extension's verdicts (``storedIndicators``). A record whose hits are matched as it's written
    /// (``IndicatorEvaluator/export``) lists none, since that match is exact.
    var recordedUndetermined: [IndicatorUndetermined]? {
        guard indicatorsUndeterminedData != nil, storedIndicators != nil else { return nil }
        return storedUndetermined
    }
}
