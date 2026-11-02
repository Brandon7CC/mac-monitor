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
/// their own in Settings ▸ Indicators. The tables also draw ``builtInMarks``, which aren't listed there.
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

// MARK: - Saving
/// The findings as user defaults keep them: only what someone changed, on top of the ``Finding/defaults`` this
/// build ships. An update can then change, add or drop a shipped finding for everyone who didn't edit it.
///
/// It's a JSON object. `entries` lists the findings in order. A shipped finding nobody edited is saved by identity
/// with its switches (`{"default": id, "isEnabled": ...}`) and takes its rule from this build. An edited shipped
/// finding, and one someone added, is saved in full. `deleted` lists the shipped findings someone deleted, so they
/// don't come back.
///
/// Each entry is decoded on its own, so one that doesn't decode loses only itself. It might have a color or rendering
/// a newer build added. It's kept as it was saved and written back after the rest.
public struct SavedFindings {
    /// The findings, in order: the saved ones, then shipped findings that are new since the last save.
    public var findings: [Finding]
    /// The shipped findings they're saved against.
    private let defaults: [Finding]
    /// The shipped findings someone deleted, by identity.
    private var deleted: Set<UUID> = []
    /// The entries that didn't decode, as `JSONSerialization` read them.
    private var undecodable: [Any] = []

    /// How many entries didn't decode.
    public var undecodableCount: Int { undecodable.count }

    /// The JSON keys of a shipped finding's switches, which a saved reference keeps.
    private static let switchKeys = ["isEnabled", "showsInCorrelation", "showsInGroups", "showsInTables"]

    /// - Parameters:
    ///   - findings: The findings, with no undecodable entries.
    ///   - defaults: The shipped findings.
    public init(_ findings: [Finding], defaults: [Finding] = Finding.defaults) {
        self.findings = findings
        self.defaults = defaults
    }

    /// Decode saved findings one entry at a time, and apply them to the shipped ones.
    ///
    /// An array is the format earlier 3.0 builds saved, every finding in full. A shipped finding in it that matches
    /// this build's version or an earlier one (``Finding/previousDefaults``) was never edited, so it follows this
    /// build. A shipped finding it doesn't list was deleted.
    ///
    /// - Parameters:
    ///   - data: The saved JSON.
    ///   - defaults: The shipped findings.
    /// - Returns: `nil` when the data is neither an object with `entries` nor an array.
    public init?(data: Data, defaults: [Finding] = Finding.defaults) {
        let object = try? JSONSerialization.jsonObject(with: data)
        let entries: [Any]
        if let saved = object as? [String: Any], let listed = saved["entries"] as? [Any] {
            entries = listed
            deleted = Set((saved["deleted"] as? [String] ?? []).compactMap(UUID.init(uuidString:)))
        } else if let array = object as? [Any] {
            entries = array
        } else {
            return nil
        }
        self.defaults = defaults
        findings = []
        let shipped = Dictionary(uniqueKeysWithValues: defaults.map { ($0.id, $0) })
        for entry in entries {
            if let reference = entry as? [String: Any], let id = reference["default"] {
                guard let id = (id as? String).flatMap(UUID.init(uuidString:)) else {
                    undecodable.append(entry)
                    continue
                }
                // A shipped finding this build no longer ships goes.
                guard var finding = shipped[id] else { continue }
                finding.applySwitches(from: reference)
                findings.append(finding)
            } else if let entryData = try? JSONSerialization.data(withJSONObject: entry, options: .fragmentsAllowed),
                      let saved = try? JSONDecoder().decode(Finding.self, from: entryData) {
                guard Finding.previousDefaults.contains(where: { $0.hasSameRule(as: saved) })
                        || shipped[saved.id].map({ $0.hasSameRule(as: saved) }) == true else {
                    findings.append(saved)
                    continue
                }
                // An unedited shipped finding from an earlier build: this build's version, with its switches.
                guard var finding = shipped[saved.id] else { continue }
                finding.copySwitches(from: saved)
                findings.append(finding)
            } else {
                undecodable.append(entry)
            }
        }
        let listed = Set(findings.map(\.id))
        if !(object is [String: Any]) {
            deleted = Set(defaults.map(\.id)).subtracting(listed)
        }
        findings += defaults.filter { !listed.contains($0.id) && !deleted.contains($0.id) }
    }

    /// The findings, then the entries that didn't decode, as the JSON object ``init(data:defaults:)`` reads.
    ///
    /// - Returns: The data to save, or `nil` if it can't be encoded.
    public func encoded() -> Data? {
        let shipped = Dictionary(uniqueKeysWithValues: defaults.map { ($0.id, $0) })
        var entries: [Any] = []
        for finding in findings {
            guard let data = try? JSONEncoder().encode(finding),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
            if let original = shipped[finding.id], original.hasSameRule(as: finding) {
                entries.append(object.filter { Self.switchKeys.contains($0.key) }
                    .merging(["default": finding.id.uuidString]) { $1 })
            } else {
                entries.append(object)
            }
        }
        let present = Set(findings.map(\.id))
        let deleted = deleted.union(defaults.map(\.id)).subtracting(present)
        return try? JSONSerialization.data(withJSONObject: [
            "entries": entries + undecodable, "deleted": deleted.map(\.uuidString).sorted(),
        ])
    }
}


// MARK: - Searching
public extension Finding {
    /// Does Settings ▸ Indicators' search find it? Every word of the search has to be in its name, its explanation or
    /// its predicate, ignoring case and accents.
    ///
    /// - Parameter search: What was typed. An empty one finds every finding.
    /// - Returns: `true` when each word is found.
    func matches(search: String) -> Bool {
        let fields = [name, explanation, predicate]
        return search.split(whereSeparator: \.isWhitespace).allSatisfy { word in
            fields.contains { $0.localizedStandardContains(word) }
        }
    }
}


// MARK: - Switches
extension Finding {
    /// Is it the same finding with the same rule, whatever its switches? The switches are whether it's on and where
    /// it shows.
    ///
    /// - Parameter other: Another finding.
    /// - Returns: `true` when only their switches differ.
    func hasSameRule(as other: Finding) -> Bool {
        var mine = self
        mine.copySwitches(from: other)
        return mine == other
    }

    /// Take another finding's switches.
    ///
    /// - Parameter other: The finding whose switches to take.
    mutating func copySwitches(from other: Finding) {
        isEnabled = other.isEnabled
        showsInCorrelation = other.showsInCorrelation
        showsInGroups = other.showsInGroups
        showsInTables = other.showsInTables
    }

    /// Take the switches a saved reference keeps. A switch it doesn't have stays as shipped.
    ///
    /// - Parameter reference: The saved reference.
    mutating func applySwitches(from reference: [String: Any]) {
        isEnabled = reference["isEnabled"] as? Bool ?? isEnabled
        showsInCorrelation = reference["showsInCorrelation"] as? Bool ?? showsInCorrelation
        showsInGroups = reference["showsInGroups"] as? Bool ?? showsInGroups
        showsInTables = reference["showsInTables"] as? Bool ?? showsInTables
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
    ///   - offered: The findings offered, as ``offered(_:)`` picks them.
    ///   - audience: Who the predicate is for.
    /// - Returns: Its predicate, any offered finding's for ``any``. It's `nil` when no finding it names is offered.
    public func predicate(offered: [Finding], for audience: PredicateAudience) -> StreamFilter.Predicate? {
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
