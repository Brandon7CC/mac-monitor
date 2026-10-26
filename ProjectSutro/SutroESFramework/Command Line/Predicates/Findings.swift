//
//  Findings.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/25/26.
//

import Foundation


// MARK: - Findings
/// What's worth a look among an event's related events: a predicate on each event's record, with what Event Facts
/// calls it. Correlation shows the findings among the events of the process an exec created, Groups among a group's
/// execs. The tables mark the events of those with ``showsInTables``. Mac Monitor ships ``defaults``, and people add
/// their own in Settings ▸ Findings. The tables also draw ``builtInMarks``, which aren't listed there.
public struct Finding: Codable, Identifiable, Hashable {
    /// A finding's color, by name, for its card, its rows' dots and its symbol.
    public enum Color: String, Codable, CaseIterable {
        case red, orange, yellow, green, teal, blue, indigo, purple, pink, gray, black, primary
    }

    /// How its symbol is drawn.
    public enum Rendering: String, Codable, CaseIterable {
        /// In ``color``.
        case monochrome
        /// In ``palette``'s colors, one a layer.
        case palette
        /// In the symbol's own colors.
        case multicolor
    }

    public var id: UUID
    /// What its card is called, such as "Reflective loading".
    public var name: String
    /// Why it's worth a look, for the card's help and the inspector.
    public var explanation: String
    /// Its SF Symbol.
    public var symbol: String
    public var color: Color
    /// How its symbol is drawn.
    public var rendering: Rendering
    /// The colors of its symbol's layers, for ``Rendering/palette``.
    public var palette: [Color]
    /// The predicate an event matches, on the event's record, as `macmonitor stream --predicate` takes one.
    public var predicate: String
    /// Does it show in Correlation, among the events of the process an exec created?
    public var showsInCorrelation: Bool
    /// Does it show in Groups, among a process group's or session's execs?
    public var showsInGroups: Bool
    /// Does its symbol mark its events in the event tables, and is it offered under the Filters button?
    public var showsInTables: Bool
    public var isEnabled: Bool

    /// - Parameters:
    ///   - id: Its identity, the same across launches.
    ///   - name: What its card is called.
    ///   - explanation: Why it's worth a look.
    ///   - symbol: Its SF Symbol.
    ///   - color: Its color.
    ///   - rendering: How its symbol is drawn.
    ///   - palette: The colors of its symbol's layers, for a palette.
    ///   - predicate: The predicate an event matches.
    ///   - correlation: Does it show in Correlation?
    ///   - groups: Does it show in Groups?
    ///   - tables: Does its symbol mark its events in the event tables?
    ///   - isEnabled: Is it on?
    public init(id: UUID = UUID(), name: String, explanation: String, symbol: String, color: Color,
                rendering: Rendering = .monochrome, palette: [Color] = [], predicate: String,
                correlation: Bool, groups: Bool, tables: Bool = false, isEnabled: Bool = true) {
        self.id = id
        self.name = name
        self.explanation = explanation
        self.symbol = symbol
        self.color = color
        self.rendering = rendering
        self.palette = palette
        self.predicate = predicate
        showsInCorrelation = correlation
        showsInGroups = groups
        showsInTables = tables
        self.isEnabled = isEnabled
    }

    /// Why its predicate can't be used, or `nil` if it can. A finding compares one event at a time: no `SUBQUERY`.
    public var problem: String? {
        do {
            _ = try StreamFilter.Predicate(predicate, for: .finding)
            return nil
        } catch {
            return (error as? CommandLineUsageError)?.message ?? error.localizedDescription
        }
    }
}

extension Finding {
    /// A saved finding. One saved before ``showsInTables`` takes the default's choice, or doesn't mark the tables. One
    /// saved before ``rendering`` is drawn in its color.
    ///
    /// - Parameter decoder: The saved findings.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let id = try container.decode(UUID.self, forKey: .id)
        self.id = id
        name = try container.decode(String.self, forKey: .name)
        explanation = try container.decode(String.self, forKey: .explanation)
        symbol = try container.decode(String.self, forKey: .symbol)
        color = try container.decode(Color.self, forKey: .color)
        rendering = try container.decodeIfPresent(Rendering.self, forKey: .rendering) ?? .monochrome
        palette = try container.decodeIfPresent([Color].self, forKey: .palette) ?? []
        predicate = try container.decode(String.self, forKey: .predicate)
        showsInCorrelation = try container.decode(Bool.self, forKey: .showsInCorrelation)
        showsInGroups = try container.decode(Bool.self, forKey: .showsInGroups)
        showsInTables = try container.decodeIfPresent(Bool.self, forKey: .showsInTables)
            ?? Self.defaults.first { $0.id == id }?.showsInTables ?? false
        isEnabled = try container.decode(Bool.self, forKey: .isEnabled)
    }
}


// MARK: - Finding filter
/// The findings whose events the Filters sheet shows only: one finding, or any finding. It's kept by identity, so its
/// predicate is read from the findings as they are now.
public enum FindingSelection: Hashable {
    /// Every offered finding's events.
    case any
    /// One finding's events, by its identity.
    case finding(UUID)

    /// The findings it can filter by: those on, marked in the tables, and whose predicate can be used.
    ///
    /// - Parameter findings: Every finding, in order.
    /// - Returns: Those offered under the Filters button.
    public static func offered(_ findings: [Finding]) -> [Finding] {
        findings.filter { $0.isEnabled && $0.showsInTables && $0.problem == nil }
    }

    /// - Parameters:
    ///   - findings: Every finding, in order.
    ///   - audience: Who the predicate is for.
    /// - Returns: Its predicate, any offered finding's for ``any``. It's `nil` when no finding it names is offered.
    public func predicate(among findings: [Finding], for audience: PredicateAudience) -> StreamFilter.Predicate? {
        let offered = Self.offered(findings)
        switch self {
        case .any:
            return .any(offered.map(\.predicate), for: audience)
        case .finding(let id):
            return offered.first { $0.id == id }.flatMap { .any([$0.predicate], for: audience) }
        }
    }
}


// MARK: - Matching
/// The findings that are on, parsed once, to find which an event is part of. Not thread-safe: use one per queue, on
/// the events' context's queue.
public final class FindingMatcher {
    private let findings: [(finding: Finding, predicate: StreamFilter.Predicate, narrow: NSPredicate?, exact: Bool)]

    /// The findings it looks for, in their cards' order.
    public var order: [Finding] { findings.map(\.finding) }

    /// - Parameter findings: The findings, in the order their cards show. Those off, or whose predicate can't be
    ///   used, are left out.
    public init(_ findings: [Finding]) {
        self.findings = findings.filter(\.isEnabled).compactMap { finding in
            guard let predicate = try? StreamFilter.Predicate(finding.predicate, for: .finding) else { return nil }
            return (finding, predicate, predicate.storePredicate, StoredEventValues.canEvaluate(predicate.parsed))
        }
    }

    /// The findings an event is part of. The store's columns rule most out first
    /// (``StreamFilter/Predicate/storePredicate``). A finding that only compares values the stored event holds as its
    /// record does is evaluated on the event itself (``StoredEventValues``); the record is encoded only for the rest:
    /// about 380 µs an exec row, which Mac Monitor's own findings and marks never need.
    ///
    /// - Parameter message: The event.
    /// - Returns: Its findings, in order.
    public func matches(_ message: ESMessage) -> [Finding] {
        let candidates = findings.filter { item in
            guard let narrow = item.narrow else { return true }
            return (try? PredicateBridge.evaluate(narrow, with: message, variables: nil)) == true
        }
        guard !candidates.isEmpty else { return [] }
        let stored = StoredEventValues(message)
        lazy var record = try? JSONSerialization.jsonObject(with: JSONEncoder().encode(message)) as? NSDictionary
        return candidates.filter { item in
            if item.exact { return stored.matches(item.predicate.parsed) }
            guard let record else { return false }
            return (try? item.predicate.evaluate(on: record)) == true
        }.map(\.finding)
    }
}


// MARK: - Stored values
/// A stored event's values as a predicate on its record sees them, for the key paths whose value on the stored event
/// is the record's in every case (`FindingTests` checks each against the synthetic corpus and the fixtures), so a
/// predicate that compares only those is evaluated without encoding the record.
final class StoredEventValues: NSObject {
    /// The key paths whose value on the stored event is the record's.
    static let keyPaths = emptyWhenNil.union(arrays).union([
        "es_event_type", "event_type", "context", "target_path", "event.exec.executable_age_ms",
        "event.exec.script_content", "event.exec.target.euid", "event.exec.target.ruid",
        "event.exec.target.is_adhoc_signed", "event.exec.target.signing_id", "event.exec.target.executable.path",
        "event.exec.dyld_exec_path", "event.create.is_quarantined", "event.rename.is_quarantined",
        "event.deleteextattr.extattr", "event.setextattr.extattr", "event.iokit_open.user_client_class",
        "event.exit.stat", "process.executable.name",
    ])
    /// Strings the store keeps as `nil` where the record writes "".
    static let emptyWhenNil: Set<String> = [
        "event.exec.target.codesigning_type", "process.file_quarantine_type", "event.exec.target.executable.name",
        "event.exec.target.file_quarantine_type",
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
    /// those key paths with constants or with each other. `ANY` only for ``arrays``. No `ALL`, `MATCHES`, `SUBQUERY`,
    /// aggregates or functions.
    ///
    /// - Parameter predicate: A parsed predicate.
    /// - Returns: Whether it can.
    static func canEvaluate(_ predicate: NSPredicate) -> Bool {
        switch predicate {
        case let compound as NSCompoundPredicate:
            return compound.subpredicates.allSatisfy { ($0 as? NSPredicate).map(canEvaluate) ?? false }
        case let comparison as NSComparisonPredicate:
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
