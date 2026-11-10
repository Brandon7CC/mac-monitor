//
//  IndicatorVerdicts.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Verdicts
/// The indicators an event matched, as it carries them from the Security Extension (``Message/indicators``) and as the
/// event store keeps them (``ESMessage/indicatorsData``). Encoded as the record's `indicators` array.
///
/// An event without verdicts (`nil`) wasn't evaluated: an older Security Extension sent it, or it came from a trace
/// that doesn't carry them, such as eslogger's or one exported before 3.1.0. Empty verdicts mean it was evaluated and
/// matched none.
///
/// A list that can't be read decodes as `nil` rather than failing its event (``KeyedDecodingContainer``'s
/// `decodeIfPresent(_:forKey:)` for verdicts), so an event is never dropped over its verdicts.
public struct IndicatorVerdicts: Codable, Hashable, Sendable {
    /// The hits, in the set's order.
    public var hits: [IndicatorHit]

    /// - Parameter hits: The hits, in the set's order: empty when the event matched none.
    public init(_ hits: [IndicatorHit] = []) {
        self.hits = hits
    }

    /// - Parameter decoder: A decoder holding the record's `indicators` array.
    /// - Throws: When it isn't an array of hits.
    public init(from decoder: Decoder) throws {
        hits = try decoder.singleValueContainer().decode([IndicatorHit].self)
    }

    /// - Parameter encoder: The encoder: writes the hits as an array.
    /// - Throws: When a hit can't be encoded.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(hits)
    }
}


// MARK: - Lenient decoding
extension KeyedDecodingContainer {
    /// Verdicts, leniently: missing, `null` or a list that can't be read (a hit without a field, one of the wrong
    /// type) is `nil`, "not evaluated", so its event still decodes. A synthesized `Decodable` conformance picks this
    /// over the generic `decodeIfPresent`, since it names the type.
    ///
    /// - Parameters:
    ///   - type: ``IndicatorVerdicts``.
    ///   - key: The key, `indicators`.
    /// - Returns: The verdicts, or `nil`.
    func decodeIfPresent(_ type: IndicatorVerdicts.Type, forKey key: Key) throws -> IndicatorVerdicts? {
        guard contains(key), (try? decodeNil(forKey: key)) == false else { return nil }
        return try? decode(IndicatorVerdicts.self, forKey: key)
    }
}


// MARK: - Undetermined indicators
/// An indicator the Security Extension couldn't rule out for an event: evaluating it needed more of the event's
/// values than its per-event scan budget or Foundation's 64 KiB window allowed, so it may or may not match. While an
/// event's hits and undetermined indicators are each under their limit (``CompiledIndicators/hitLimit``,
/// ``CompiledIndicators/undeterminedLimit``), an indicator in neither didn't match. A list at its limit may have been
/// cut short, and then one in neither may match.
///
/// It encodes flat, as one entry of the record's `indicators_undetermined`: the hit's keys (``IndicatorHit``) and
/// `reason`. Decoding is as strict as a hit's, so a decoder that fills in missing values can't make one up.
public struct IndicatorUndetermined: Codable, Hashable, Sendable {
    /// The indicator, as a hit would describe it.
    public let hit: IndicatorHit
    /// Why it wasn't decided.
    public let reason: UndeterminedReason

    /// - Parameters:
    ///   - hit: The indicator, as a hit would describe it.
    ///   - reason: Why it wasn't decided.
    public init(_ hit: IndicatorHit, reason: UndeterminedReason) {
        self.hit = hit
        self.reason = reason
    }

    /// - Parameter decoder: A decoder holding one entry of the record's `indicators_undetermined` array.
    /// - Throws: What decoding its hit throws, or when `reason` is missing, `null` or not a name.
    public init(from decoder: Decoder) throws {
        hit = try IndicatorHit(from: decoder)
        reason = try decoder.container(keyedBy: CodingKeys.self).decodePresent(UndeterminedReason.self,
                                                                                forKey: .reason)
    }

    /// - Parameter encoder: The encoder: writes the hit's keys and `reason` in one object.
    /// - Throws: When a value can't be encoded.
    public func encode(to encoder: Encoder) throws {
        try hit.encode(to: encoder)
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(reason, forKey: .reason)
    }

    /// The key an entry adds to its hit's.
    private enum CodingKeys: String, CodingKey {
        case reason
    }
}


/// Why an indicator wasn't decided for an event. Any other name, from a newer producer, is kept as it's written, so
/// a reason this build doesn't know never fails its record.
public enum UndeterminedReason: Codable, Hashable, Sendable {
    /// Evaluating it needed more of the event's values than the Security Extension's per-event scan budget allows.
    case scanBudget
    /// A value that isn't ASCII was longer than the 64 KiB the Security Extension compares, and what it compared
    /// didn't decide it.
    case valueLimit
    /// A reason this build doesn't know.
    case other(String)

    /// The reasons this build knows, as the telemetry schema lists them.
    public static let known: [UndeterminedReason] = [.scanBudget, .valueLimit]

    /// - Parameter rawValue: Its name, as a record writes it.
    public init(rawValue: String) {
        switch rawValue {
        case "scan_budget": self = .scanBudget
        case "value_limit": self = .valueLimit
        default: self = .other(rawValue)
        }
    }

    /// Its name, as a record writes it.
    public var rawValue: String {
        switch self {
        case .scanBudget: "scan_budget"
        case .valueLimit: "value_limit"
        case .other(let name): name
        }
    }

    /// - Parameter decoder: The decoder.
    /// - Throws: When it isn't a string, or is empty: every reason has a name.
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let name = try container.decode(String.self)
        guard !name.isEmpty else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "A reason has no name.")
        }
        self.init(rawValue: name)
    }

    /// - Parameter encoder: The encoder.
    /// - Throws: When it can't be encoded.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}


/// The indicators the Security Extension couldn't rule out for an event (``Message/indicators_undetermined``), as
/// the event store keeps them (``ESMessage/indicatorsUndeterminedData``): encoded as the record's
/// `indicators_undetermined` array, in the set's order, at most ``CompiledIndicators/undeterminedLimit``.
///
/// `nil` means every indicator was decided, or nothing evaluated the event: it's never empty. A list that can't be
/// read decodes as `nil`, as verdicts do, so an event is never dropped over it.
public struct UndeterminedIndicators: Codable, Hashable, Sendable {
    /// The indicators, in the set's order.
    public var entries: [IndicatorUndetermined]

    /// - Parameter entries: The indicators, in the set's order.
    public init(_ entries: [IndicatorUndetermined]) {
        self.entries = entries
    }

    /// - Parameter decoder: A decoder holding the record's `indicators_undetermined` array.
    /// - Throws: When it isn't an array of undetermined indicators.
    public init(from decoder: Decoder) throws {
        entries = try decoder.singleValueContainer().decode([IndicatorUndetermined].self)
    }

    /// - Parameter encoder: The encoder: writes the entries as an array.
    /// - Throws: When an entry can't be encoded.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(entries)
    }
}


extension KeyedDecodingContainer {
    /// Undetermined indicators, leniently, as verdicts are read: missing, `null` or a list that can't be read is
    /// `nil`, so its event still decodes.
    ///
    /// - Parameters:
    ///   - type: ``UndeterminedIndicators``.
    ///   - key: The key, `indicators_undetermined`.
    /// - Returns: The indicators, or `nil`.
    func decodeIfPresent(_ type: UndeterminedIndicators.Type, forKey key: Key) throws -> UndeterminedIndicators? {
        guard contains(key), (try? decodeNil(forKey: key)) == false else { return nil }
        return try? decode(UndeterminedIndicators.self, forKey: key)
    }
}
