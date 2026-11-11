//
//  IndicatorMatcher.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Matching
/// The indicators that are on, parsed once, to find which an event is part of. Not thread-safe: use one per queue, on
/// the events' context's queue.
public final class IndicatorMatcher {
    /// An indicator that's on, with its parsed predicate, the store predicate that rules most events out first, and
    /// whether the predicate compares only values the stored event holds as its record does (``StoredEventValues``).
    private typealias Item = (indicator: Indicator, predicate: StreamFilter.Predicate, narrow: NSPredicate?,
                              exact: Bool)
    /// The indicators that are on, in order.
    private let indicators: [Item]
    /// The indicators that can match each event type, in order, for those whose predicate names their types.
    private let byType: [String: [Int]]
    /// The indicators whose predicate names no event types, which any event can match.
    private let anyType: [Int]
    /// For an indicator with the same predicate as an earlier one, byte for byte (``CompiledIndicators/Source``), the
    /// earlier one's index: it's evaluated once.
    private let sameAs: [Int: Int]

    /// The indicators it looks for, in their cards' order.
    public var order: [Indicator] { indicators.map(\.indicator) }

    /// - Parameter indicators: The indicators, in the order their cards show. Those off, or whose predicate can't be
    ///   used, are left out.
    public init(_ indicators: [Indicator]) {
        self.indicators = indicators.filter(\.isEnabled).compactMap { indicator in
            guard let predicate = try? StreamFilter.Predicate(indicator.predicate, for: .indicator) else { return nil }
            return (indicator, predicate, predicate.storePredicate, StoredEventValues.canEvaluate(predicate.parsed))
        }
        var byType: [String: [Int]] = [:], anyType: [Int] = []
        for (index, item) in self.indicators.enumerated() {
            guard let types = PredicateEventTypes.eventTypes(of: item.predicate.parsed) else {
                anyType.append(index)
                continue
            }
            types.forEach { byType[$0, default: []].append(index) }
        }
        self.byType = byType
        self.anyType = anyType
        var first: [CompiledIndicators.Source: Int] = [:], sameAs: [Int: Int] = [:]
        for (index, item) in self.indicators.enumerated() {
            let source = CompiledIndicators.Source(item.predicate.source)
            if let earlier = first[source] { sameAs[index] = earlier } else { first[source] = index }
        }
        self.sameAs = sameAs
    }

    /// The indicators an event is part of. Only those that can match its type are looked at
    /// (``PredicateEventTypes/eventTypes(of:)``). An indicator that only compares values the stored event holds as its
    /// record does is evaluated on the event itself (``StoredEventValues``). For the rest the store's columns rule most
    /// out first (``StreamFilter/Predicate/storePredicate``), and the record is encoded only for those left: about
    /// 380 µs an exec row, which Mac Monitor's own indicators and marks never need.
    ///
    /// - Parameter message: The event.
    /// - Returns: Its indicators, in order.
    public func matches(_ message: ESMessage) -> [Indicator] {
        let typed = message.es_event_type.flatMap { byType[$0] } ?? []
        let indices = anyType.isEmpty ? typed : typed.isEmpty ? anyType : (typed + anyType).sorted()
        guard !indices.isEmpty else { return [] }
        let stored = StoredEventValues(message)
        lazy var record = try? JSONSerialization.jsonObject(with: JSONEncoder().encode(message)) as? NSDictionary
        var verdicts: [Int: Bool] = [:]
        return indices.filter { index in
            if let earlier = sameAs[index], let verdict = verdicts[earlier] { return verdict }
            let item = indicators[index]
            let verdict: Bool
            if item.exact {
                /// No narrowing first: that's the same comparisons again.
                verdict = stored.matches(item.predicate.parsed)
            } else if let narrow = item.narrow,
                      (try? PredicateBridge.evaluate(narrow, with: message, variables: nil)) != true {
                verdict = false
            } else {
                verdict = record.map { (try? item.predicate.evaluate(on: $0)) == true } ?? false
            }
            verdicts[index] = verdict
            return verdict
        }.map { indicators[$0].indicator }
    }
}


// MARK: - Stored values
/// A stored event's values as a predicate on its record sees them, for the key paths whose value on the stored event
/// is the record's in every case (`IndicatorTests` checks each against the synthetic corpus and the fixtures), so a
/// predicate that compares only those is evaluated without encoding the record.
final class StoredEventValues: NSObject {
    /// The key paths whose value on the stored event is the record's.
    static let keyPaths = emptyWhenNil.union(arrays).union([
        "es_event_type", "event_type", "context", "target_path", "event.exec.executable_age_ms",
        "event.exec.script_content", "event.exec.target.euid", "event.exec.target.ruid",
        "event.exec.target.is_adhoc_signed", "event.exec.target.signing_id", "event.exec.target.executable.path",
        "event.exec.dyld_exec_path", "event.exec.command_line", "event.create.is_quarantined",
        "event.rename.is_quarantined", "event.deleteextattr.extattr", "event.setextattr.extattr",
        "event.iokit_open.user_client_class", "event.iokit_open.driver_bundle_id", "event.close.modified",
        "event.close.file_type", "event.close.target.name",
        "event.close.mach_o_type", "event.mmap.file_type", "event.mmap.mach_o_type", "event.rename.file_type",
        "event.rename.mach_o_type", "event.exit.stat",
        "process.executable.name", "process.executable.path", "process.signing_id", "process.is_platform_binary",
        "process.is_adhoc_signed", "process.team_id", "event.uipc_connect.file.stat.st_uid",
        "event.xpc_connect.service_name", "event.xpc_connect.service_domain_type_string",
    ])
    /// Strings the store keeps as `nil` where the record writes "".
    static let emptyWhenNil: Set<String> = [
        "event.exec.target.codesigning_type", "process.file_quarantine_type", "event.exec.target.executable.name",
        "event.exec.target.file_quarantine_type", "process.codesigning_type",
    ]
    /// Arrays of strings the store keeps encoded, which `ANY` compares.
    static let arrays: Set<String> = ["event.exec.env"]
    /// The comparisons that read a value as the record path reads it.
    private static let operators: Set<NSComparisonPredicate.Operator> = [
        .equalTo, .notEqualTo, .lessThan, .lessThanOrEqualTo, .greaterThan, .greaterThanOrEqualTo, .in, .beginsWith,
        .endsWith, .contains, .like,
    ]
    
    let message: ESMessage
    
    /// - Parameter message: The stored event.
    init(_ message: ESMessage) {
        self.message = message
    }
    
    /// Can a predicate be evaluated on a stored event, as on its record? Only `AND`, `OR` and `NOT` of comparisons of
    /// those key paths with constants or with each other, and payload tests (``PredicateEventTypes/payloadTest(_:)``).
    /// `ANY` only for ``arrays``. No `ALL`, `MATCHES`, `SUBQUERY`, aggregates or functions.
    ///
    /// - Parameter predicate: A parsed predicate.
    /// - Returns: Whether it can.
    static func canEvaluate(_ predicate: NSPredicate) -> Bool {
        switch predicate {
        case let compound as NSCompoundPredicate:
            return compound.subpredicates.allSatisfy { ($0 as? NSPredicate).map(canEvaluate) ?? false }
        case let comparison as NSComparisonPredicate:
            if PredicateEventTypes.payloadTest(comparison) != nil { return true }
            let left = comparison.leftExpression
            guard left.expressionType == .keyPath, keyPaths.contains(left.keyPath),
                  operators.contains(comparison.predicateOperatorType) else { return false }
            switch comparison.comparisonPredicateModifier {
            case .direct: break
            case .any where arrays.contains(left.keyPath): break
            default: return false
            }
            return isConstant(comparison.rightExpression) || isStoredKeyPath(comparison.rightExpression)
        default:
            return false
        }
    }

    /// - Parameter expression: The right side of a comparison.
    /// - Returns: Whether it's a constant, or a set of constants (`IN {"a", "b"}`).
    private static func isConstant(_ expression: NSExpression) -> Bool {
        switch expression.expressionType {
        case .constantValue: return true
        case .aggregate: return (expression.collection as? [NSExpression])?.allSatisfy(isConstant) ?? false
        default: return false
        }
    }

    /// - Parameter expression: The right side of a comparison.
    /// - Returns: Whether it's one of ``keyPaths``, other than an array.
    private static func isStoredKeyPath(_ expression: NSExpression) -> Bool {
        expression.expressionType == .keyPath && keyPaths.subtracting(arrays).contains(expression.keyPath)
    }

    /// Evaluate a predicate ``canEvaluate(_:)`` passed. One that raises doesn't match, as on the record.
    ///
    /// - Parameter predicate: The predicate.
    /// - Returns: Whether the event matches.
    func matches(_ predicate: NSPredicate) -> Bool {
        (try? PredicateBridge.evaluate(predicate, with: self, variables: nil)) == true
    }
    
    /// A key path's value on the stored event: "" for a string the record writes as "" and the store keeps as `nil`,
    /// where the object holding it is there. An exec's environment is decoded from the store.
    ///
    /// - Parameter keyPath: One of ``keyPaths``.
    /// - Returns: The value.
    override func value(forKeyPath keyPath: String) -> Any? {
        if keyPath == "event.exec.env" { return message.event.exec.map { $0.env as NSArray } }
        if let type = PredicateEventTypes.payloads[keyPath] {
            /// A payload test reads only whether the record has the payload, which is whether it's of that type.
            return message.es_event_type == type ? NSNumber(value: true) : nil
        }
        let value = message.value(forKeyPath: keyPath)
        guard value == nil, Self.emptyWhenNil.contains(keyPath),
              let dot = keyPath.lastIndex(of: "."), message.value(forKeyPath: String(keyPath[..<dot])) != nil
        else { return value }
        return ""
    }
    
    /// A single key's value, as a key path's: `NSPredicate` reads a key path of one key this way.
    ///
    /// - Parameter key: One of ``keyPaths``.
    /// - Returns: The value.
    override func value(forKey key: String) -> Any? {
        value(forKeyPath: key)
    }
}
