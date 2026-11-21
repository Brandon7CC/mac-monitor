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
/// (``ESMessage/recordedUndetermined``). Hits matched as it's written never have them.
///
/// An encoder is given indicators by encoding inside ``encoding(with:_:)``, which an `ESMessage` reads as it encodes.
/// Any encoder works, the streaming one too, since its `userInfo` is always empty.
public final class RecordIndicators: @unchecked Sendable {
    /// Finds the indicators an event matches, or `nil` to match none (``stored``). Not thread-safe, so one per
    /// encoder, used on its context's queue.
    private let matcher: IndicatorMatcher?
    /// Mac Monitor's own indicators, by identity, for each hit's `default` and `edited`: as the Security Extension
    /// last sent them to Mac Monitor (``IndicatorEngine/cachedBaseline(in:)``), so a hit matched here says what one
    /// the Security Extension stamped says. Where none were kept, as in `macmonitor`, they're this build's.
    private let shipped: [UUID: Indicator]
    /// The indicator pack those are, for each hit's `pack`: 0 for a build's own, which aren't a pack.
    private let pack: Int

    /// The indicators the encoding on this thread or task lists, if any.
    @TaskLocal static var current: RecordIndicators?

    /// - Parameter indicators: The indicators, in Settings' order. Those off, or whose predicate can't be used, are
    ///   left out.
    public convenience init(_ indicators: [Indicator]) {
        self.init(indicators, shipped: Indicator.byID(IndicatorEngine.cachedBaseline()),
                  pack: IndicatorEngine.cachedPack())
    }

    /// - Parameters:
    ///   - indicators: The indicators, in Settings' order. Those off, or whose predicate can't be used, are left
    ///     out.
    ///   - shipped: Mac Monitor's own indicators, by identity.
    ///   - pack: The indicator pack those are, or 0 for a build's own.
    public init(_ indicators: [Indicator], shipped: [UUID: Indicator], pack: Int = 0) {
        matcher = IndicatorMatcher(indicators)
        self.shipped = shipped
        self.pack = pack
    }

    /// - Parameter matcher: Finds the indicators an event matches, or `nil` to match none.
    private init(matcher: IndicatorMatcher?) {
        self.matcher = matcher
        shipped = [:]
        pack = 0
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
            IndicatorHit($0, against: shipped, pack: pack, evaluatedBy: .export)
        }
    }
}


// MARK: - Example
public extension RecordIndicators {
    /// A predicate that finds the events an indicator matched, by its name: the predicate editor's example. The name
    /// is the one the linked pack gives Property list modified, so a pack that renames it keeps the example finding
    /// its events.
    static let exampleQuery: String = {
        let name = Indicator.defaults.first { $0.id == Indicator.uuid(0x2A) }?.name ?? "Property list modified"
        return #"ANY indicators.name ==[c] "\#(name)""#
    }()
}


// MARK: - Indicator hits
/// An indicator an event matched: what an export record's `indicators` lists, with who evaluated it. The Security
/// Extension makes them as it captures the event (``CompiledIndicators``), and they travel with it
/// (``IndicatorVerdicts``). Mac Monitor makes them as it writes a record of an event that has none
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
    /// Did this Mac change one Mac Monitor ships (``Indicator/sameIndicator(as:)``)? Never for one it doesn't ship.
    public let edited: Bool
    /// Who matched it.
    public let evaluated_by: IndicatorEvaluator
    /// The indicator's revision, which its pack raises whenever the indicator changes, or `nil` for one without. An
    /// edited one keeps the revision it was edited from.
    public let revision: Int?
    /// The indicator pack this Mac had when it matched, by its sequence, for one Mac Monitor ships. `nil` for one
    /// this Mac added, and when the indicators are a build's own rather than a pack's.
    public let pack: Int?
    /// What made it match: the comparisons of its rule the event passed, each with the value the event had
    /// (``IndicatorMatchedField``). For a sequence, those of its steps this event matched, as it completed it.
    /// `nil` when its rule compares nothing but the event's type, and for a hit Mac Monitor made as it wrote a
    /// record, which only the Security Extension explains.
    public var matched: [IndicatorMatchedField]?

    /// - Parameters:
    ///   - indicator: The indicator.
    ///   - isDefault: Does Mac Monitor ship it?
    ///   - edited: Did this Mac change it? Only one Mac Monitor ships can be.
    ///   - pack: The indicator pack the shipped indicators are, or 0 for a build's own.
    ///   - evaluatedBy: Who matched it.
    public init(_ indicator: Indicator, isDefault: Bool, edited: Bool = false, pack: Int = 0,
                evaluatedBy: IndicatorEvaluator) {
        id = indicator.id
        name = indicator.name
        tactic = indicator.tactic?.name
        tactic_id = indicator.tactic?.identifier
        technique = indicator.technique
        severity = indicator.severity
        self.isDefault = isDefault
        self.edited = isDefault && edited
        evaluated_by = evaluatedBy
        revision = indicator.revision
        self.pack = isDefault && pack > 0 ? pack : nil
    }

    /// A hit that says whether Mac Monitor ships its indicator, and whether this Mac edited it.
    ///
    /// - Parameters:
    ///   - indicator: The indicator.
    ///   - defaults: The indicators Mac Monitor ships, by identity.
    ///   - pack: The indicator pack those are, or 0 for a build's own.
    ///   - evaluatedBy: Who matched it.
    public init(_ indicator: Indicator, against defaults: [UUID: Indicator], pack: Int = 0,
                evaluatedBy: IndicatorEvaluator) {
        let original = defaults[indicator.id]
        self.init(indicator, isDefault: original != nil,
                  edited: original.map { !indicator.sameIndicator(as: $0) } ?? false, pack: pack,
                  evaluatedBy: evaluatedBy)
    }

    /// Strictly, whatever the decoder: Open Trace's fills in what's missing, so a hit without its identity, name or
    /// `default` would otherwise be kept with made-up values and exported again as a real verdict.
    ///
    /// - Parameter decoder: A decoder holding one entry of the record's `indicators` array.
    /// - Throws: When a required key is missing or `null`, the identity isn't a UUID, the severity isn't one this
    ///   build knows, or the evaluator has no name. `edited` is required: a hit stored by a build before it isn't
    ///   read, so its event counts as not evaluated, and is matched again as it's exported. `revision`, `pack` and
    ///   `matched` may be missing, as they are in a trace Mac Monitor 3.1 wrote.
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
        revision = try container.decodeIfPresent(Int.self, forKey: .revision)
        pack = try container.decodeIfPresent(Int.self, forKey: .pack)
        /// What it matched explains the verdict and isn't part of it: one that can't be read is dropped, not the hit.
        matched = try? container.decodeIfPresent([IndicatorMatchedField].self, forKey: .matched)
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
        try container.encode(revision, forKey: .revision)
        try container.encode(pack, forKey: .pack)
        try container.encode(matched, forKey: .matched)
    }

    /// A hit's keys in a record.
    private enum CodingKeys: String, CodingKey {
        case id, name, tactic, tactic_id, technique, severity, edited, evaluated_by, revision, pack, matched
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
