//
//  Indicator.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/25/26.
//

import Foundation


// MARK: - Indicators
/// What's worth a look among an event's related events: a predicate on each event's record, with what Event Facts
/// calls it. Correlation shows the indicators among the events of the process an exec created, Groups among a group's
/// execs. The tables mark each event an indicator that's on matches, as its ``tableMarks`` say. Mac Monitor ships
/// ``defaults``, and people add their own in Settings > Indicators. The tables also draw ``builtInMarks``, which aren't
/// listed there.
public struct Indicator: Codable, Identifiable, Hashable {
    /// How the event tables mark the events it matches: any of its dot in the row, its symbol in the row, and the
    /// event's label in its color, each chosen on its own. None leaves its events unmarked, and Any indicator, under
    /// the Filters button, leaves them out too.
    public struct TableMarks: OptionSet, Hashable, Sendable {
        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// Its color's dot in the row.
        public static let dot = TableMarks(rawValue: 1 << 0)
        /// Its symbol in the row.
        public static let symbol = TableMarks(rawValue: 1 << 1)
        /// The event's label in its color, so its events stand out.
        public static let label = TableMarks(rawValue: 1 << 2)

        /// Each mark, as Settings > Indicators lists them, with the name it's saved by and its title there.
        public static let each: [(mark: TableMarks, name: String, title: String)] = [
            (.dot, "dot", "Dot"), (.symbol, "symbol", "Symbol"), (.label, "label", "Label color"),
        ]

        /// - Parameter names: The marks' names, as they're saved. One this build doesn't know is left out.
        public init(names: [String]) {
            self = Self.each.reduce(into: []) { marks, each in
                if names.contains(each.name) { marks.insert(each.mark) }
            }
        }

        /// The marks one choice made before they were chosen apart: `label`, `symbol`, `dot` or `off`. A label marked
        /// the row with the symbol and the dot too, and a symbol with the dot.
        ///
        /// - Parameter legacy: The choice's name.
        /// - Returns: The marks, or `nil` for a name that was never a choice.
        public init?(legacy: String) {
            switch legacy {
            case "label": self = [.dot, .symbol, .label]
            case "symbol": self = [.dot, .symbol]
            case "dot": self = .dot
            case "off": self = []
            default: return nil
            }
        }

        /// The marks' names, as they're saved, in ``each``'s order.
        public var names: [String] {
            Self.each.filter { contains($0.mark) }.map(\.name)
        }

        /// The marks' titles, as in "Dot, Symbol", or "Not marked" for none.
        public var title: String {
            isEmpty ? "Not marked" : Self.each.filter { contains($0.mark) }.map(\.title).joined(separator: ", ")
        }
    }

    /// An indicator's color, by name, for its card, its rows' dots and its symbol.
    public enum Color: String, Codable, CaseIterable {
        case red, orange, yellow, green, teal, blue, indigo, purple, pink, gray, black, primary
    }

    public var id: UUID
    /// What its card is called, such as "Reflective loading".
    public var name: String
    /// What it finds and why that's worth a look, for its row's help and Event Facts' Indicators popover.
    public var description: String
    /// Its SF Symbol, drawn in ``color``.
    public var symbol: String
    public var color: Color
    /// What it matches: a predicate on one event, or a sequence of events.
    public var rule: Rule
    /// How the event tables mark its events.
    public var tableMarks: TableMarks
    public var isEnabled: Bool
    /// The ATT&CK tactic it's for, or `nil` for none. Settings > Indicators groups indicators by it.
    public var tactic: Tactic?
    /// The ATT&CK technique it finds, such as `T1543.001`, or `nil` for none.
    public var technique: String?
    /// How closely a match is worth looking at. It's part of the indicator, so Mac-wide, and every record that lists
    /// the indicator has it.
    public var severity: IndicatorSeverity
    /// Which version of it this is, for one an indicator pack ships: it goes up whenever anything Mac Monitor shows or
    /// runs changes. `nil` for one someone wrote.
    public var revision: Int?
    /// The oldest Mac Monitor that can run it, for one an indicator pack ships, or `nil` for any. A newer one is kept
    /// but not run (``isSupported``).
    public var minEngine: ReleaseVersion?

    /// Does its symbol mark its events in the event tables? Setting it changes only the symbol, as builds before
    /// ``tableMarks`` saved it.
    public var showsInTables: Bool {
        get { tableMarks.contains(.symbol) }
        set { if newValue { tableMarks.insert(.symbol) } else { tableMarks.remove(.symbol) } }
    }

    /// - Parameters:
    ///   - id: Its identity, the same across launches.
    ///   - name: What its card is called.
    ///   - description: What it finds and why that's worth a look.
    ///   - symbol: Its SF Symbol.
    ///   - color: Its color.
    ///   - rule: What it matches.
    ///   - tables: How the event tables mark its events.
    ///   - isEnabled: Is it on?
    ///   - tactic: The ATT&CK tactic it's for.
    ///   - technique: The ATT&CK technique it finds.
    ///   - severity: How strong a sign a match is.
    ///   - revision: Which version of a pack's indicator it is.
    ///   - minEngine: The oldest Mac Monitor that can run it.
    public init(id: UUID = UUID(), name: String, description: String, symbol: String, color: Color, rule: Rule,
                tables: TableMarks = .dot, isEnabled: Bool = true, tactic: Tactic? = nil, technique: String? = nil,
                severity: IndicatorSeverity = .medium, revision: Int? = nil, minEngine: ReleaseVersion? = nil) {
        self.id = id
        self.name = name
        self.description = description
        self.symbol = symbol
        self.color = color
        self.rule = rule
        tableMarks = tables
        self.isEnabled = isEnabled
        self.tactic = tactic
        self.technique = technique
        self.severity = severity
        self.revision = revision
        self.minEngine = minEngine
    }

    /// An indicator whose rule is a predicate on one event.
    ///
    /// - Parameters:
    ///   - id: Its identity, the same across launches.
    ///   - name: What its card is called.
    ///   - description: What it finds and why that's worth a look.
    ///   - symbol: Its SF Symbol.
    ///   - color: Its color.
    ///   - predicate: The predicate an event matches.
    ///   - tables: How the event tables mark its events.
    ///   - isEnabled: Is it on?
    ///   - tactic: The ATT&CK tactic it's for.
    ///   - technique: The ATT&CK technique it finds.
    ///   - severity: How strong a sign a match is.
    public init(id: UUID = UUID(), name: String, description: String, symbol: String, color: Color, predicate: String,
                tables: TableMarks = .dot, isEnabled: Bool = true,
                tactic: Tactic? = nil, technique: String? = nil, severity: IndicatorSeverity = .medium) {
        self.init(id: id, name: name, description: description, symbol: symbol, color: color, rule: .event(predicate),
                  tables: tables, isEnabled: isEnabled, tactic: tactic, technique: technique, severity: severity)
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, description, symbol, color, predicate, tableMarks, isEnabled, tactic, technique, severity
        case kind, sequence, revision, minEngine
        /// How builds before ``tableMarks`` saved the marks, still read: one choice, or whether the symbol showed.
        case tableMark, showsInTables
        /// What Mac Monitor 3.0 and the 3.1 betas called ``description``, still read.
        case explanation
    }

    /// Decode an indicator. Only its name and predicate are needed, so one written by hand to share imports
    /// (``IndicatorExchange``): it's a new, orange, magnifying glass that's on and marks the tables with a dot. One
    /// saved before ``tableMarks`` has the one `tableMark` chosen (``TableMarks/init(legacy:)``), or earlier still
    /// `showsInTables`: its symbol and dot, or else the dot. A tactic this build doesn't know is none, and a severity
    /// that's missing or unknown is medium. A description saved as `explanation`, as earlier builds saved it, is read
    /// too, and keys this build doesn't know, such as the `rendering`, `palette`, `showsInCorrelation` and
    /// `showsInGroups` earlier builds wrote, are ignored. Its name, description, symbol and technique have to
    /// be within ``Limits``. Its `kind` says what its rule is (``Rule/Kind``): none, or `event`, is a `predicate`, and
    /// `sequence` is a `sequence`. A kind this build doesn't know isn't read. A pack's `revision` and `minEngine` are
    /// read when present.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: When its name or rule is missing, a key isn't what it should be, a field is past its limit, or it's a
    ///   kind of rule this build doesn't know.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try container.decodeIfPresent(String.self, forKey: .kind)
        switch kind.map(Rule.Kind.init(rawValue:)) ?? .event {
        case .event:
            rule = .event(try container.decode(String.self, forKey: .predicate))
        case .sequence:
            rule = .sequence(try container.decode(IndicatorSequence.self, forKey: .sequence))
        case nil:
            throw DecodingError.dataCorruptedError(forKey: .kind, in: container, debugDescription: """
                It's a rule of kind \(kind ?? ""), which this Mac Monitor can't run. Update Mac Monitor to use it.
                """)
        }
        revision = try container.decodeIfPresent(Int.self, forKey: .revision)
        minEngine = try container.decodeIfPresent(ReleaseVersion.self, forKey: .minEngine)
        id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        name = try container.decode(String.self, forKey: .name)
        description = try container.decodeIfPresent(String.self, forKey: .description)
            ?? container.decodeIfPresent(String.self, forKey: .explanation) ?? ""
        symbol = try container.decodeIfPresent(String.self, forKey: .symbol) ?? "exclamationmark.magnifyingglass"
        color = try container.decodeIfPresent(Color.self, forKey: .color) ?? .orange
        isEnabled = try container.decodeIfPresent(Bool.self, forKey: .isEnabled) ?? true
        if let names = try container.decodeIfPresent([String].self, forKey: .tableMarks) {
            tableMarks = TableMarks(names: names)
        } else if let legacy = try container.decodeIfPresent(String.self, forKey: .tableMark) {
            guard let marks = TableMarks(legacy: legacy) else {
                throw DecodingError.dataCorruptedError(forKey: .tableMark, in: container,
                                                       debugDescription: "'\(legacy)' isn't a table mark.")
            }
            tableMarks = marks
        } else {
            let shows = try container.decodeIfPresent(Bool.self, forKey: .showsInTables) == true
            tableMarks = shows ? [.dot, .symbol] : .dot
        }
        tactic = (try? container.decodeIfPresent(String.self, forKey: .tactic)).flatMap { $0 }
            .flatMap(Tactic.init(rawValue:))
        technique = try container.decodeIfPresent(String.self, forKey: .technique)
        severity = (try? container.decodeIfPresent(String.self, forKey: .severity)).flatMap { $0 }
            .flatMap(IndicatorSeverity.init(rawValue:)) ?? .medium
        if let problem = limitProblem {
            throw DecodingError.dataCorruptedError(forKey: .name, in: container, debugDescription: problem)
        }
    }

    /// Encode an indicator, its marks by name: `["dot", "symbol"]`. A rule on one event is its `predicate`, with no
    /// `kind`, as builds before sequences wrote it, and a sequence is `kind` `sequence` and its `sequence`.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: When a value can't be encoded.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(description, forKey: .description)
        try container.encode(symbol, forKey: .symbol)
        try container.encode(color, forKey: .color)
        switch rule {
        case .event(let predicate):
            try container.encode(predicate, forKey: .predicate)
        case .sequence(let sequence):
            try container.encode(Rule.Kind.sequence.rawValue, forKey: .kind)
            try container.encode(sequence, forKey: .sequence)
        }
        try container.encode(tableMarks.names, forKey: .tableMarks)
        try container.encode(isEnabled, forKey: .isEnabled)
        try container.encodeIfPresent(tactic, forKey: .tactic)
        try container.encodeIfPresent(technique, forKey: .technique)
        try container.encode(severity, forKey: .severity)
        try container.encodeIfPresent(revision, forKey: .revision)
        try container.encodeIfPresent(minEngine, forKey: .minEngine)
    }

    /// Why its rule can't be used, or `nil` if it can. A predicate compares one event at a time: no `SUBQUERY`. A
    /// sequence's steps are each such a predicate, tied together as ``IndicatorSequence/problem`` checks. One that
    /// needs a newer Mac Monitor says so (``isSupported``).
    public var problem: String? {
        if let minEngine, !isSupported { return "It needs Mac Monitor \(minEngine) or later." }
        switch rule {
        case .event(let predicate):
            return Self.problem(with: predicate)
        case .sequence(let sequence):
            return sequence.problem
        }
    }

    /// Why a predicate on one event can't be used, as ``problem`` says it.
    ///
    /// - Parameter predicate: The predicate.
    /// - Returns: The reason, or `nil` when it can be used.
    static func problem(with predicate: String) -> String? {
        do {
            _ = try StreamFilter.Predicate(predicate, for: .indicator)
            return nil
        } catch {
            return (error as? CommandLineUsageError)?.message ?? error.localizedDescription
        }
    }
}


// MARK: - Searching
public extension Indicator {
    /// Does Settings > Indicators' search find it? Every word of the search has to be in its name, its description,
    /// its predicates, its tactic or its technique, ignoring case and accents.
    ///
    /// - Parameter search: What was typed. An empty one finds every indicator.
    /// - Returns: `true` when each word is found.
    func matches(search: String) -> Bool {
        let fields = [name, description, tactic?.name ?? "", tactic?.identifier ?? "", technique ?? ""]
            + rule.predicates.map(\.predicate)
        return search.split(whereSeparator: \.isWhitespace).allSatisfy { word in
            fields.contains { $0.localizedStandardContains(word) }
        }
    }
}


// MARK: - Switches
extension Indicator {
    /// Is it the same indicator with the same rule, whatever its switches, its tactic, technique and severity? The
    /// switches are whether it's on and how the tables mark its events. A pack's revision and minimum Mac Monitor
    /// aren't compared either: an entry saved before either existed, or under another revision, with the same rule is
    /// the same.
    ///
    /// - Parameter other: Another indicator.
    /// - Returns: `true` when only their switches, tactics, techniques, severities, revisions or minimum Mac Monitors
    ///   differ.
    func hasSameRule(as other: Indicator) -> Bool {
        var mine = self
        mine.copySwitches(from: other)
        mine.tactic = other.tactic
        mine.technique = other.technique
        mine.severity = other.severity
        mine.revision = other.revision
        mine.minEngine = other.minEngine
        return mine == other
    }

    /// Take another indicator's switches.
    ///
    /// - Parameter other: The indicator whose switches to take.
    mutating func copySwitches(from other: Indicator) {
        isEnabled = other.isEnabled
        tableMarks = other.tableMarks
    }

    /// Take the switches a saved reference keeps. A switch it doesn't have stays as shipped.
    ///
    /// - Parameter reference: The saved reference.
    mutating func applySwitches(from reference: [String: Any]) {
        isEnabled = reference["isEnabled"] as? Bool ?? isEnabled
        if let names = reference["tableMarks"] as? [String] {
            tableMarks = TableMarks(names: names)
        } else if let marks = (reference["tableMark"] as? String).flatMap(TableMarks.init(legacy:)) {
            tableMarks = marks
        } else if let shows = reference["showsInTables"] as? Bool {
            showsInTables = shows
        }
    }

    /// Take the tactic, technique and severity a saved entry has. One it doesn't have, or one that isn't valid (such
    /// as a technique past ``Limits``), stays as shipped, and a `null` tactic or technique is none.
    ///
    /// - Parameter entry: The saved entry, a reference or an indicator in full.
    mutating func applyClassification(from entry: [String: Any]) {
        if let severity = (entry["severity"] as? String).flatMap(IndicatorSeverity.init(rawValue:)) {
            self.severity = severity
        }
        if let tactic = entry["tactic"] {
            self.tactic = tactic is NSNull ? nil : (tactic as? String).flatMap(Tactic.init(rawValue:)) ?? self.tactic
        }
        if let technique = entry["technique"] {
            if technique is NSNull {
                self.technique = nil
            } else if let technique = technique as? String, Self.isTechnique(technique) {
                self.technique = technique
            }
        }
    }
}


// MARK: - Indicator filter
/// The indicators whose events the Filters sheet shows only: one indicator, or any indicator. It's kept by identity,
/// and filters by the indicators each event's record lists (``StreamFilter/Predicate/listing(_:for:)``): the Security
/// Extension's stored verdicts when it has them, else the indicators matched as they are now. So it shows the events
/// the tables' dots mark.
public enum IndicatorSelection: Hashable {
    /// The events of every offered indicator that marks the tables.
    case any
    /// One indicator's events, by its identity.
    case indicator(UUID)

    /// The indicators it can filter by: every one that's on and whose predicate can be used, whether or not it marks
    /// the tables.
    ///
    /// - Parameter indicators: Every indicator, in order.
    /// - Returns: Those that can be filtered by one at a time. Any indicator, under the Filters button, shows the
    ///   events of those that mark the tables.
    public static func offered(_ indicators: [Indicator]) -> [Indicator] {
        indicators.filter { $0.isEnabled && $0.problem == nil }
    }

    /// - Parameters:
    ///   - offered: The indicators offered, as ``offered(_:)`` picks them.
    ///   - audience: Who the predicate is for.
    /// - Returns: Its predicate, on the record's `indicators`: for ``any``, any offered indicator that marks the
    ///   tables. It's `nil` when no indicator it names is offered.
    public func predicate(offered: [Indicator], for audience: PredicateAudience) -> StreamFilter.Predicate? {
        switch self {
        case .any:
            return .listing(offered.filter { !$0.tableMarks.isEmpty }.map(\.id), for: audience)
        case .indicator(let id):
            return .listing(offered.filter { $0.id == id }.map(\.id), for: audience)
        }
    }
}
