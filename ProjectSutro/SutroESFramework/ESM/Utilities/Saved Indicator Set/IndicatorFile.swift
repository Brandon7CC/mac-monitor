//
//  IndicatorFile.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
import EndpointSecurity


// MARK: - Limits
/// How large the Mac's indicator set may grow. The Security Extension checks a saved file and every request against
/// them (``IndicatorFile/validate(_:)``), and runs no set past one, so a writer can't make it spend more than they
/// allow on each event.
public enum IndicatorLimits {
    /// The most bytes in the saved file or a request, checked before parsing: 4 MiB.
    public static let maxFileBytes = 4 << 20
    /// The most indicators in the set.
    public static let maxIndicators = 2_048
    /// The longest predicate, in characters, as Settings takes one (``StreamFilter/Predicate/maxLength``).
    public static let maxPredicateLength = StreamFilter.Predicate.maxLength
    /// The most nodes in all of the set's programs.
    public static let maxNodes = 65_536
    /// The most rules the Security Extension runs on one event type.
    public static let maxRulesPerType = 256
}


// MARK: - Indicator file
/// The Mac's indicator set as the Security Extension keeps it (Security Extension context): `indicators.json` in
/// ``RootFileStore/systemDirectory``, `root:wheel`, the file 0600 and the directory 0700. Only the Security Extension
/// reads it. Mac Monitor and `macmonitor` change it through requests (``IndicatorRequest``).
///
/// ```json
/// { "version": 1, "saved": { "entries": [ { "default": "...", "isEnabled": true } ], "deleted": [] } }
/// ```
///
/// `saved` is ``SavedIndicators``: only what someone changed on top of the indicators this build ships, so a shipped
/// indicator nobody edited takes each build's improvements. An entry this build can't read, such as a newer build's
/// rule over several events, is kept and written back. A file of a newer ``version`` is left as it is, and the set
/// can't be changed until Mac Monitor is updated.
public struct IndicatorFile {
    /// The version this build writes and reads.
    public static let currentVersion = 1
    /// The saved file, where an unreadable one is kept, and temporary files' prefix.
    public static let layout = RootFileStore.Layout(fileName: "indicators.json",
                                                    unreadableFileName: "indicators.unreadable.json",
                                                    temporaryPrefix: ".indicators.",
                                                    maxBytes: IndicatorLimits.maxFileBytes, noun: "indicator set")
    /// The marker kept while a saved file is read and compiled (``SavedIndicatorSet``): one found at startup means
    /// the last try crashed the Security Extension.
    public static let loadingLayout = RootFileStore.Layout(fileName: "indicators.loading",
                                                           unreadableFileName: "indicators.loading.unreadable",
                                                           temporaryPrefix: ".indicators.loading.", maxBytes: 0,
                                                           noun: "indicator loading marker")

    /// The file's version.
    public var version: Int
    /// The indicators.
    public var saved: SavedIndicators

    /// - Parameter saved: The indicators.
    public init(_ saved: SavedIndicators) {
        version = Self.currentVersion
        self.saved = saved
    }

    /// The file's bytes.
    ///
    /// - Returns: The JSON, or `nil` if an indicator can't be encoded.
    public func encoded() -> Data? {
        guard let saved = saved.encodedObject() else { return nil }
        return try? JSONSerialization.data(withJSONObject: ["version": version, "saved": saved],
                                           options: [.sortedKeys])
    }

    /// Read a saved file. Its indicators are then checked as a set (``validate(_:)``).
    ///
    /// - Parameters:
    ///   - data: The file's bytes.
    ///   - defaults: The indicators this build ships.
    /// - Returns: The file.
    /// - Throws: ``IndicatorFileError/unsupportedVersion(_:)`` for a newer file, or
    ///   ``IndicatorFileError/malformed(_:)``.
    public static func decode(_ data: Data, defaults: [Indicator] = Indicator.defaults) throws(IndicatorFileError)
        -> IndicatorFile {
        guard let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw .malformed("It isn't a JSON object.")
        }
        /// A number, not `true`: JSON booleans read as numbers too.
        guard let number = object["version"] as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else {
            throw .malformed("It has no version.")
        }
        let version = number.intValue
        guard version >= 1 else { throw .malformed("It can't be version \(version).") }
        guard version <= currentVersion else { throw .unsupportedVersion(version) }
        guard let saved = SavedIndicators(object: object["saved"], defaults: defaults) else {
            throw .malformed("It has no saved indicators.")
        }
        return IndicatorFile(saved)
    }
}


// MARK: - Validation
extension IndicatorFile {
    /// Check a set as the Security Extension keeps it: at most ``IndicatorLimits/maxIndicators``, no identity twice,
    /// and every predicate within ``IndicatorLimits/maxPredicateLength``.
    ///
    /// - Parameter indicators: The set, in order.
    /// - Throws: ``IndicatorFileError`` for the first problem.
    public static func validate(_ indicators: [Indicator]) throws(IndicatorFileError) {
        guard indicators.count <= IndicatorLimits.maxIndicators else { throw .tooManyIndicators(indicators.count) }
        var seen = Set<UUID>()
        seen.reserveCapacity(indicators.count)
        for indicator in indicators {
            guard seen.insert(indicator.id).inserted else { throw .duplicateID(indicator.id, indicator.name) }
            try checkPredicateLength(of: indicator)
        }
    }

    /// Check indicators a request brings, before they join the set: no identity twice, each within ``Indicator/Limits``
    /// and ``IndicatorLimits/maxPredicateLength``, and every event type a predicate names one this build knows, in
    /// any branch, `NOT` included. A predicate that's otherwise unusable joins, and is listed as a problem.
    ///
    /// - Parameter indicators: The request's indicators.
    /// - Throws: ``IndicatorFileError`` for the first problem.
    public static func validateIncoming(_ indicators: [Indicator]) throws(IndicatorFileError) {
        try validate(indicators)
        for indicator in indicators {
            if let problem = indicator.limitProblem { throw .pastLimit(indicator.name, problem) }
            guard let parsed = try? StreamFilter.Predicate.parse(indicator.predicate, for: .indicator) else { continue }
            let unknown = PredicateEventTypes.namedEventTypes(in: parsed)
                .filter { eventStringToType(from: $0) == ES_EVENT_TYPE_LAST }.sorted()
            guard unknown.isEmpty else { throw .unknownEventTypes(indicator.name, unknown) }
        }
    }

    /// Check a compiled set against what the Security Extension runs: at most ``IndicatorLimits/maxNodes`` in all,
    /// and ``IndicatorLimits/maxRulesPerType`` on any event type.
    ///
    /// - Parameter compiled: The set.
    /// - Throws: ``IndicatorFileError/tooManyNodes(_:)`` or ``IndicatorFileError/tooManyRules(type:count:)``.
    public static func validate(_ compiled: CompiledIndicators) throws(IndicatorFileError) {
        guard compiled.nodeCount <= IndicatorLimits.maxNodes else { throw .tooManyNodes(compiled.nodeCount) }
        if let busiest = compiled.busiestType(), busiest.rules > IndicatorLimits.maxRulesPerType {
            throw .tooManyRules(type: eventTypeToString(from: es_event_type_t(rawValue: UInt32(busiest.type))),
                                count: busiest.rules)
        }
    }

    /// - Parameter indicator: An indicator.
    /// - Throws: ``IndicatorFileError/predicateTooLong(_:)`` when its predicate is past
    ///   ``IndicatorLimits/maxPredicateLength`` characters. A short one in bytes is short in characters, so only a
    ///   long one is counted.
    private static func checkPredicateLength(of indicator: Indicator) throws(IndicatorFileError) {
        let predicate = indicator.predicate
        guard predicate.utf8.count > IndicatorLimits.maxPredicateLength,
              predicate.count > IndicatorLimits.maxPredicateLength else { return }
        throw .predicateTooLong(indicator.name)
    }
}


// MARK: - Errors
/// Why a saved indicator file, or the indicators a request brings, can't be used.
public enum IndicatorFileError: Error, Equatable, CustomStringConvertible {
    /// A file a newer Mac Monitor wrote.
    case unsupportedVersion(Int)
    /// Not an indicator file, and why.
    case malformed(String)
    /// More than ``IndicatorLimits/maxIndicators``.
    case tooManyIndicators(Int)
    /// Two indicators with one identity: the identity, and the second's name.
    case duplicateID(UUID, String)
    /// An indicator's predicate is longer than ``IndicatorLimits/maxPredicateLength``: its name.
    case predicateTooLong(String)
    /// A field is past ``Indicator/Limits``: the indicator's name, and which.
    case pastLimit(String, String)
    /// A predicate names event types this build doesn't know: the indicator's name, and the types.
    case unknownEventTypes(String, [String])
    /// The programs have more nodes in all than ``IndicatorLimits/maxNodes``.
    case tooManyNodes(Int)
    /// More rules run on one event type than ``IndicatorLimits/maxRulesPerType``.
    case tooManyRules(type: String, count: Int)

    /// The problem, as a sentence.
    public var description: String {
        switch self {
        case .unsupportedVersion(let version):
            "It's indicator file version \(version), from a newer Mac Monitor."
        case .malformed(let reason): reason
        case .tooManyIndicators(let count):
            "It has \(count) indicators. The Security Extension keeps \(IndicatorLimits.maxIndicators) at most."
        case .duplicateID(let id, let name):
            "“\(name)” has the identity \(id.uuidString), which another indicator has too."
        case .predicateTooLong(let name):
            "“\(name)” has a predicate longer than \(IndicatorLimits.maxPredicateLength) characters."
        case .pastLimit(let name, let problem): "“\(name)”: \(problem)"
        case .unknownEventTypes(let name, let types):
            "“\(name)” names event types this Mac Monitor doesn't know: \(types.joined(separator: ", "))."
        case .tooManyNodes(let count):
            "Its rules have \(count) parts in all. The Security Extension runs \(IndicatorLimits.maxNodes) at most."
        case .tooManyRules(let type, let count):
            "\(count) indicators run on \(type). The Security Extension runs \(IndicatorLimits.maxRulesPerType) on "
                + "one event type at most."
        }
    }
}
