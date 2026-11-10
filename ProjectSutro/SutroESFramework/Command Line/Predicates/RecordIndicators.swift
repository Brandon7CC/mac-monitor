//
//  RecordIndicators.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/7/26.
//

import Foundation


// MARK: - Record indicators
/// The indicators an export record lists under `indicators`. Export telemetry, `macmonitor stream`, Event Facts' JSON
/// tab, ⌘C and a search that names `indicators` or `indicators_undetermined` write the key: an event's stored verdicts
/// when it has them, the Security Extension's (``ESMessage/storedIndicators``), else those of these indicators that are
/// on and match it, tagged ``IndicatorEvaluator/export``. ``stored`` writes only the verdicts an event carries, as
/// `macmonitor stream` does: an event the Security Extension didn't evaluate has no key. Records encoded to match an
/// indicator don't write it, so a predicate never reads another indicator's matches, stored or not. Beside stored
/// verdicts, a record also lists under `indicators_undetermined` those the Security Extension couldn't rule out
/// (``ESMessage/recordedUndetermined``); hits matched as it's written never have them.
///
/// An encoder is given indicators by encoding inside ``encoding(with:_:)``, which an `ESMessage` reads as it encodes.
/// Any encoder works, the streaming one too, since its `userInfo` is always empty.
public final class RecordIndicators: @unchecked Sendable {
    /// Finds the indicators an event matches, or `nil` to match none (``stored``). Not thread-safe, so one per
    /// encoder, used on its context's queue.
    private let matcher: IndicatorMatcher?
    /// The indicators Mac Monitor ships, by identity, for each hit's `default` and `edited`.
    private let shipped = CompiledIndicators.shippedDefaults

    /// The indicators the encoding on this thread or task lists, if any.
    @TaskLocal static var current: RecordIndicators?

    /// - Parameter indicators: The indicators, in Settings' order. Those off, or whose predicate can't be used, are
    ///   left out.
    public init(_ indicators: [Indicator]) {
        matcher = IndicatorMatcher(indicators)
    }

    /// - Parameter matcher: Finds the indicators an event matches, or `nil` to match none.
    private init(matcher: IndicatorMatcher?) {
        self.matcher = matcher
    }

    /// Only the verdicts each event carries, matching nothing: `macmonitor stream`'s records, whose events the
    /// Security Extension evaluated as it captured them. It holds no matcher, so one serves every encoder.
    public static let stored = RecordIndicators(matcher: nil)

    /// Encode records that list these indicators.
    ///
    /// - Parameters:
    ///   - indicators: The indicators, or `nil` to list none.
    ///   - body: Encodes the records.
    /// - Returns: What `body` returns.
    /// - Throws: What `body` throws.
    public static func encoding<T>(with indicators: RecordIndicators?, _ body: () throws -> T) rethrows -> T {
        try $current.withValue(indicators, operation: body)
    }

    /// The hits an event's record lists when it has no stored verdicts: these indicators, matched now. Matching may
    /// encode the event's record itself, without them.
    ///
    /// - Parameter message: The event, on its context's queue.
    /// - Returns: A hit for each indicator it matches, in order, tagged ``IndicatorEvaluator/export``, or `nil` for
    ///   ``stored``, which matches none: the record then has no key.
    func entries(for message: ESMessage) -> [IndicatorHit]? {
        guard let matcher else { return nil }
        return Self.$current.withValue(nil) { matcher.matches(message) }.map {
            IndicatorHit($0, against: shipped, evaluatedBy: .export)
        }
    }
}


// MARK: - Example
public extension RecordIndicators {
    /// A predicate that finds the events an indicator matched, by its name: the predicate editor's example.
    static let exampleQuery = #"ANY indicators.name ==[c] "Plist modified""#
}


// MARK: - Indicator hits
/// An indicator an event matched: what an export record's `indicators` lists, with who evaluated it. The Security
/// Extension makes them as it captures the event (``CompiledIndicators``), and they travel with it
/// (``IndicatorVerdicts``); Mac Monitor makes them as it writes a record of an event that has none
/// (``RecordIndicators``). The wire's shape is the record's, so an imported trace keeps its verdicts.
public struct IndicatorHit: Codable, Hashable, Sendable {
    /// The indicator's identity.
    public let id: UUID
    /// Its name.
    public let name: String
    /// Its ATT&CK tactic's name, or `nil`.
    public let tactic: String?
    /// Its ATT&CK tactic's identity, such as `TA0003`, or `nil`.
    public let tactic_id: String?
    /// Its ATT&CK technique, or `nil`.
    public let technique: String?
    /// How strong a sign a match is.
    public let severity: IndicatorSeverity
    /// Is it one of Mac Monitor's defaults, which Mac Monitor ships? The record's `default`.
    public let isDefault: Bool
    /// Did this Mac change one Mac Monitor ships (``Indicator/sameDetection(as:)``)? Never for one it doesn't ship.
    public let edited: Bool
    /// Who matched it.
    public let evaluated_by: IndicatorEvaluator

    /// - Parameters:
    ///   - indicator: The indicator.
    ///   - isDefault: Does Mac Monitor ship it?
    ///   - edited: Did this Mac change it? Only one Mac Monitor ships can be.
    ///   - evaluatedBy: Who matched it.
    public init(_ indicator: Indicator, isDefault: Bool, edited: Bool = false, evaluatedBy: IndicatorEvaluator) {
        id = indicator.id
        name = indicator.name
        tactic = indicator.tactic?.name
        tactic_id = indicator.tactic?.identifier
        technique = indicator.technique
        severity = indicator.severity
        self.isDefault = isDefault
        self.edited = isDefault && edited
        evaluated_by = evaluatedBy
    }

    /// A hit that says whether Mac Monitor ships its indicator, and whether this Mac edited it.
    ///
    /// - Parameters:
    ///   - indicator: The indicator.
    ///   - defaults: The indicators Mac Monitor ships, by identity.
    ///   - evaluatedBy: Who matched it.
    public init(_ indicator: Indicator, against defaults: [UUID: Indicator], evaluatedBy: IndicatorEvaluator) {
        let original = defaults[indicator.id]
        self.init(indicator, isDefault: original != nil,
                  edited: original.map { !indicator.sameDetection(as: $0) } ?? false, evaluatedBy: evaluatedBy)
    }

    /// Strictly, whatever the decoder: Open Trace's fills in what's missing, so a hit without its identity, name or
    /// `default` would otherwise be kept with made-up values and exported again as a real verdict.
    ///
    /// - Parameter decoder: A decoder holding one entry of the record's `indicators` array.
    /// - Throws: When a required key is missing or `null`, the identity isn't a UUID, the severity isn't one this
    ///   build knows, or the evaluator has no name. `edited` is required: a hit stored by a build before it isn't
    ///   read, so its event counts as not evaluated, and is matched again as it's exported.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard let id = UUID(uuidString: try container.decodePresent(String.self, forKey: .id)) else {
            throw DecodingError.dataCorruptedError(forKey: .id, in: container, debugDescription: "Not a UUID.")
        }
        self.id = id
        name = try container.decodePresent(String.self, forKey: .name)
        tactic = try container.decodeIfPresent(String.self, forKey: .tactic)
        tactic_id = try container.decodeIfPresent(String.self, forKey: .tactic_id)
        technique = try container.decodeIfPresent(String.self, forKey: .technique)
        severity = try container.decodePresent(IndicatorSeverity.self, forKey: .severity)
        isDefault = try container.decodePresent(Bool.self, forKey: .isDefault)
        edited = try container.decodePresent(Bool.self, forKey: .edited)
        evaluated_by = try container.decodePresent(IndicatorEvaluator.self, forKey: .evaluated_by)
    }

    /// Every key, `null` for none.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: When a value can't be encoded.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(tactic, forKey: .tactic)
        try container.encode(tactic_id, forKey: .tactic_id)
        try container.encode(technique, forKey: .technique)
        try container.encode(severity, forKey: .severity)
        try container.encode(isDefault, forKey: .isDefault)
        try container.encode(edited, forKey: .edited)
        try container.encode(evaluated_by, forKey: .evaluated_by)
    }

    /// A hit's keys in a record.
    private enum CodingKeys: String, CodingKey {
        case id, name, tactic, tactic_id, technique, severity, edited, evaluated_by
        /// `default` is a Swift keyword, so the property is ``isDefault``.
        case isDefault = "default"
    }
}

extension KeyedDecodingContainer {
    /// A value that must be there: a decoder that fills in missing values, such as Open Trace's, can't make one up.
    ///
    /// - Parameters:
    ///   - type: The value's type.
    ///   - key: Its key.
    /// - Returns: The value.
    /// - Throws: `keyNotFound` when the key is missing or `null`, else what decoding the value throws.
    func decodePresent<T: Decodable>(_ type: T.Type, forKey key: Key) throws -> T {
        guard contains(key), try !decodeNil(forKey: key) else {
            throw DecodingError.keyNotFound(key, .init(codingPath: codingPath, debugDescription: "Required."))
        }
        return try decode(type, forKey: key)
    }
}

/// Who matched an event's indicator: the Security Extension as it captured the event, or Mac Monitor as it wrote the
/// record. Any other name, from a newer producer, is kept as it's written.
public enum IndicatorEvaluator: Codable, Hashable, Sendable {
    /// The Security Extension, as it captured the event.
    case securityExtension
    /// Mac Monitor, as it wrote the record.
    case export
    /// A producer this build doesn't know.
    case other(String)

    /// The producers this build knows, as the telemetry schema lists them.
    public static let known: [IndicatorEvaluator] = [.securityExtension, .export]

    /// - Parameter rawValue: Its name, as a record writes it.
    public init(rawValue: String) {
        switch rawValue {
        case "security_extension": self = .securityExtension
        case "export": self = .export
        default: self = .other(rawValue)
        }
    }

    /// Its name, as a record writes it.
    public var rawValue: String {
        switch self {
        case .securityExtension: "security_extension"
        case .export: "export"
        case .other(let name): name
        }
    }

    /// - Parameter decoder: The decoder.
    /// - Throws: When it isn't a string, or is empty: every producer has a name.
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let name = try container.decode(String.self)
        guard !name.isEmpty else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "An evaluator has no name.")
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
