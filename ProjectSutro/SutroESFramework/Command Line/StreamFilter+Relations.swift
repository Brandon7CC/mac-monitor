//
//  StreamFilter+Relations.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/23/26.
//

import Foundation


// MARK: - Related events
/// The events a search predicate's `SUBQUERY` goes through, related to the event being searched.
///
/// `SUBQUERY(process_group, $e, $e.es_event_type == "ES_EVENT_TYPE_NOTIFY_CREATE").@count > 0` matches an event whose
/// process group created a file. Inside a `SUBQUERY`, `$e.path` is the related event's and a plain key path the
/// searched event's, so `$e.process.pid == process.pid` joins the two, and `$e.mach_time > mach_time` puts the related
/// event after. Not `global_seq_num`: each Endpoint Security client numbers its own events. `events` relates every event to every other, for events nothing else relates. An event is
/// never related to itself.
public enum PredicateRelation: String, CaseIterable {
    /// Every event recorded, or in the trace.
    case events
    /// The events of the processes in the event's process group.
    case processGroup = "process_group"
    /// The events of the processes in the event's session.
    case sessionGroup = "session_group"
    /// The events of the process the event created, its `EXEC` target or `FORK` child, as Correlation shows them.
    case correlated
    /// The other events of the event's process.
    case processEvents = "process_events"

    /// What it relates, for the predicate editor.
    public var summary: String {
        switch self {
        case .events: return "Every other event"
        case .processGroup: return "Events in the same process group"
        case .sessionGroup: return "Events in the same session"
        case .correlated: return "Events of the process it created (EXEC or FORK)"
        case .processEvents: return "Other events of the same process"
        }
    }

    /// Every relation's name, for errors: "events, process_group, …".
    static var names: String { allCases.map(\.rawValue).joined(separator: ", ") }

    /// Which events a related event is among, by its own process.
    ///
    /// - Parameter record: A related event's record.
    /// - Returns: Its group, or `nil` if it has none.
    func group(ofRelated record: NSDictionary) -> AnyHashable? {
        switch self {
        case .events: return ""
        case .processGroup: return Self.hashable(record, "process.group_id")
        case .sessionGroup: return Self.hashable(record, "process.session_id")
        case .correlated, .processEvents: return Self.hashable(record, "process.audit_token_string")
        }
    }

    /// Which events relate to a searched event.
    ///
    /// - Parameter record: The searched event's record.
    /// - Returns: The group its related events are among, or `nil` if it has none.
    func group(ofSearched record: NSDictionary) -> AnyHashable? {
        switch self {
        case .events: return ""
        case .processGroup:
            return Self.hashable(record, "event.exec.target.group_id") ?? Self.hashable(record, "process.group_id")
        case .sessionGroup:
            return Self.hashable(record, "event.exec.target.session_id") ?? Self.hashable(record, "process.session_id")
        case .correlated:
            return Self.hashable(record, "event.exec.target.audit_token_string")
                ?? Self.hashable(record, "event.fork.child.audit_token_string")
        case .processEvents: return Self.hashable(record, "process.audit_token_string")
        }
    }

    /// - Parameters:
    ///   - record: A record.
    ///   - keyPath: A key path to a string or a number.
    /// - Returns: The value, or `nil` if it's anything else.
    private static func hashable(_ record: NSDictionary, _ keyPath: String) -> AnyHashable? {
        hashable(record.value(forKeyPath: keyPath))
    }

    /// - Parameter value: A value.
    /// - Returns: The value if it's a string or a number, to group or look events up by, else `nil`.
    static func hashable(_ value: Any?) -> AnyHashable? {
        switch value {
        case let string as NSString: return string
        case let number as NSNumber: return number
        default: return nil
        }
    }
}


// MARK: - Subqueries
/// A search predicate's `SUBQUERY`s of related events, and the events each collected.
///
/// Evaluating a `SUBQUERY` on every event, through every other, would take each event's record once per event. So
/// each `SUBQUERY` is split. Its conditions on the related event alone (`$e.es_event_type == …`), joined by `AND`,
/// pick the events it keeps, once each, as ``collect(_:)`` is given every event before any is searched. Its conditions
/// on both events join them, for each searched event, on the events kept in its group, looked up by an equality
/// (`$e.path == path`) when there is one. Not thread-safe: each ``StreamFilter/Predicate`` has its own.
final class RelatedEvents {
    /// The most related events one `SUBQUERY` keeps, about as many records as a search keeps in memory at once.
    static let limit = 20_000
    /// The most pairs of a searched and a related event one `SUBQUERY` compares in a search, a few seconds' worth:
    /// `NSPredicate` takes microseconds a pair. An equality's lookup compares only the events it finds.
    static let pairLimit = 250_000

    /// Why a `SUBQUERY` failed during the evaluation in progress, if one did.
    var failure: String?
    /// The predicate's `MATCHES`, rewritten for its `SUBQUERY`s' conditions too.
    private let matches: BoundedMatches
    private var subqueries: [Subquery] = []

    /// Does the predicate have a `SUBQUERY`?
    var isEmpty: Bool { subqueries.isEmpty }

    /// The events any `SUBQUERY` might keep, as the store can narrow them: `nil` when one can't be narrowed.
    var storePredicate: NSPredicate? {
        let narrowed = subqueries.compactMap(\.storePredicate)
        guard !narrowed.isEmpty, narrowed.count == subqueries.count else { return nil }
        return narrowed.count == 1 ? narrowed[0] : NSCompoundPredicate(orPredicateWithSubpredicates: narrowed)
    }

    /// - Parameter matches: The predicate's `MATCHES`.
    init(matches: BoundedMatches) {
        self.matches = matches
    }

    /// Replace each `SUBQUERY` in a predicate with its related events, and evaluate the rest first: `NSPredicate`
    /// evaluates `AND` and `OR` in order and stops once it knows, so `SUBQUERY(…) AND es_event_type == …` only
    /// goes through related events for the events of that type.
    ///
    /// - Parameters:
    ///   - predicate: A predicate ``PredicateGuard`` passed.
    ///   - audience: Who an error is for.
    /// - Returns: The predicate, its `SUBQUERY`s evaluated on the events ``collect(_:)`` kept.
    /// - Throws: ``CommandLineUsageError`` for a `MATCHES` pattern that isn't a regular expression.
    func rewrite(_ predicate: NSPredicate, for audience: PredicateAudience) throws -> NSPredicate {
        switch predicate {
        case let compound as NSCompoundPredicate:
            let subpredicates = compound.subpredicates.compactMap { $0 as? NSPredicate }
            let ordered = subpredicates.filter { !$0.contains(where: Self.isSubquery) }
                + subpredicates.filter { $0.contains(where: Self.isSubquery) }
            return NSCompoundPredicate(type: compound.compoundPredicateType,
                                       subpredicates: try ordered.map { try rewrite($0, for: audience) })
        case let comparison as NSComparisonPredicate where comparison.contains(where: Self.isSubquery):
            return NSComparisonPredicate(leftExpression: try rewrite(comparison.leftExpression, for: audience),
                                         rightExpression: try rewrite(comparison.rightExpression, for: audience),
                                         modifier: comparison.comparisonPredicateModifier,
                                         type: comparison.predicateOperatorType, options: comparison.options)
        default:
            return predicate
        }
    }

    /// - Parameters:
    ///   - expression: An expression ``PredicateGuard`` passed.
    ///   - audience: Who an error is for.
    /// - Returns: The expression, each `SUBQUERY` in it a block returning its related events.
    private func rewrite(_ expression: NSExpression, for audience: PredicateAudience) throws -> NSExpression {
        guard expression.contains(where: Self.isSubquery) else { return expression }
        switch expression.expressionType {
        case .subquery:
            let subquery = try Subquery(expression, matches: matches, for: audience)
            subqueries.append(subquery)
            return NSExpression(block: { [unowned self] object, _, _ in self.related(subquery, to: object) },
                                arguments: [])
        case .function:
            return NSExpression(forFunction: try rewrite(expression.operand, for: audience),
                                selectorName: expression.function,
                                arguments: try (expression.arguments ?? []).map { try rewrite($0, for: audience) })
        case .aggregate:
            let members = (expression.collection as? [NSExpression]) ?? []
            return NSExpression(forAggregate: try members.map { try rewrite($0, for: audience) })
        default:
            return expression
        }
    }

    /// Keep each event a `SUBQUERY` picks. Give it every event before evaluating the predicate on any.
    ///
    /// - Parameter record: An event's record.
    /// - Throws: ``PredicateFailure`` if a `SUBQUERY`'s conditions on the related event can't be evaluated on it.
    func collect(_ record: NSDictionary) throws {
        let related = PredicateRecord(record)
        for subquery in subqueries {
            matches.failure = nil
            try subquery.collect(related)
            if let failure = matches.failure { throw PredicateFailure(description: failure) }
        }
    }

    /// - Parameters:
    ///   - subquery: A `SUBQUERY`.
    ///   - object: The searched event.
    /// - Returns: Its related events that the `SUBQUERY` matches, none once anything failed.
    private func related(_ subquery: Subquery, to object: Any?) -> NSArray {
        guard failure == nil, let searched = object as? PredicateRecord else { return [] }
        do {
            return try subquery.matches(for: searched)
        } catch {
            failure = "\(error)"
            return []
        }
    }

    /// - Parameter expression: An expression.
    /// - Returns: Is it a `SUBQUERY`?
    private static func isSubquery(_ expression: NSExpression) -> Bool {
        expression.expressionType == .subquery
    }
}


// MARK: - One subquery
extension RelatedEvents {
    /// One `SUBQUERY(relation, $e, conditions)`, and the related events it kept.
    final class Subquery {
        let relation: PredicateRelation
        /// Its variable's name, `e` for `$e`.
        let variable: String
        /// Its conditions on the related event alone, which pick the events it keeps. `nil` keeps every one.
        private let picks: NSPredicate?
        /// What the store can narrow the events it might keep to, from its conditions on the related event alone:
        /// `nil` when nothing can be said, so every event is a candidate.
        let storePredicate: NSPredicate?
        /// Its conditions on both events. `nil` matches each event it kept.
        private let joins: NSPredicate?
        /// An equality in ``joins``, `$e.path == expression`, to look a searched event's related events up by.
        private let lookup: (path: String, searched: NSExpression)?
        /// The events kept, by ``PredicateRelation/group(ofRelated:)``.
        private var kept: [AnyHashable: [PredicateRecord]] = [:]
        private var count = 0
        /// The pairs of events compared so far, up to ``RelatedEvents/pairLimit``.
        private var compared = 0
        /// Did it pick more than ``RelatedEvents/limit``?
        private var overflowed = false
        /// The events kept by group and their ``lookup`` path's value, built on first use. `nil` once a value
        /// can't be looked up by, an array or an object: those are each compared instead.
        private lazy var index: [Pair: [PredicateRecord]]? = makeIndex()
        /// Which events each group kept are which event, to leave a searched event out of its own related events
        /// without comparing it with each: built for a group on first use, and dropped when the group keeps another.
        private var sameness: [AnyHashable: Sameness] = [:]

        /// A group and a value.
        private struct Pair: Hashable {
            let group: AnyHashable
            let value: AnyHashable
        }

        /// - Parameters:
        ///   - subquery: A `SUBQUERY` ``PredicateGuard`` passed.
        ///   - matches: The predicate's `MATCHES`.
        ///   - audience: Who an error is for.
        /// - Throws: ``CommandLineUsageError`` for a `MATCHES` pattern that isn't a regular expression.
        init(_ subquery: NSExpression, matches: BoundedMatches, for audience: PredicateAudience) throws {
            guard let collection = subquery.collection as? NSExpression,
                  let relation = PredicateRelation(rawValue: collection.keyPath) else {
                throw CommandLineUsageError("\(audience.name) can't use \(subquery.description).",
                                            command: audience.command)
            }
            self.relation = relation
            variable = subquery.variable
            let conditions = subquery.predicate
            let conjuncts = (conditions as? NSCompoundPredicate)?.compoundPredicateType == .and
                ? (conditions as! NSCompoundPredicate).subpredicates.compactMap { $0 as? NSPredicate } : [conditions]
            let joining = conjuncts.filter(Self.readsSearched), picking = conjuncts.filter { !Self.readsSearched($0) }
            /// The conditions joined by `AND`, or `nil` for none.
            func and(_ predicates: [NSPredicate]) -> NSPredicate? {
                predicates.count > 1 ? NSCompoundPredicate(andPredicateWithSubpredicates: predicates) : predicates.first
            }
            let picked = and(picking)
            picks = try picked.map { try matches.rewrite($0, for: audience) }
            storePredicate = picked.flatMap { [variable] in StoreNarrowing.predicate(for: $0, variable: variable) }
            joins = try and(joining).map { try matches.rewrite($0, for: audience) }
            lookup = joining.lazy.compactMap { [variable] in Self.lookup(in: $0, variable) }.first
        }

        /// Keep an event if the conditions on the related event alone pick it.
        ///
        /// - Parameter related: The event's record.
        /// - Throws: Why the conditions couldn't be evaluated on it.
        func collect(_ related: PredicateRecord) throws {
            guard !overflowed, let group = relation.group(ofRelated: related.values) else { return }
            if let picks, try !PredicateBridge.evaluate(picks, with: related, variables: [variable: related]) { return }
            guard count < RelatedEvents.limit else {
                overflowed = true
                (kept, sameness) = ([:], [:])
                return
            }
            kept[group, default: []].append(related)
            sameness[group] = nil
            count += 1
        }

        /// - Parameter searched: The searched event.
        /// - Returns: Its related events that the conditions on both events match.
        /// - Throws: ``PredicateFailure`` once the `SUBQUERY` kept too many events or compared too many pairs, or why
        ///   the conditions couldn't be evaluated.
        func matches(for searched: PredicateRecord) throws -> NSArray {
            guard !overflowed else {
                throw PredicateFailure(description: """
                    SUBQUERY(\(relation.rawValue), $\(variable), …) picks more than \(RelatedEvents.limit) related \
                    events: narrow it with conditions on $\(variable) alone, joined by AND.
                    """)
            }
            guard let group = relation.group(ofSearched: searched.values), var related = kept[group] else {
                return NSArray()
            }
            if let lookup, let index, let value = try PredicateRelation.hashable(
                PredicateBridge.evaluate(lookup.searched, with: searched, variables: nil)) {
                related = index[Pair(group: group, value: value)] ?? []
            }
            guard let joins else { return excluding(searched, from: related, in: group) }
            compared += related.count
            guard compared <= RelatedEvents.pairLimit else {
                throw PredicateFailure(description: """
                    SUBQUERY(\(relation.rawValue), $\(variable), …) compares more than \
                    \(RelatedEvents.pairLimit.formatted()) pairs of events: narrow it with conditions on $\(variable) \
                    alone, or join on an equality, such as $\(variable).process.pid == process.pid.
                    """)
            }
            /// The searched event itself is left out after, from the few the conditions match.
            return try PredicateBridge.filter(related, with: joins, object: searched, variable: variable)
                .compactMap { $0 as? PredicateRecord }.filter { !$0.isSame(as: searched) } as NSArray
        }
        
        /// A group's events without the searched event itself (and any copy of it), in their order: the group's
        /// array, or a view of it that skips those, never a copy. Filtering every one per searched event cost about
        /// 10 ms with 20,000 kept.
        ///
        /// - Parameters:
        ///   - searched: The searched event.
        ///   - related: The group's events.
        ///   - group: The group.
        /// - Returns: Its related events.
        private func excluding(_ searched: PredicateRecord, from related: [PredicateRecord],
                               in group: AnyHashable) -> NSArray {
            let same = sameness[group] ?? Sameness(related)
            sameness[group] = same
            let skipped = same.indexes(of: searched)
            return skipped.isEmpty ? related as NSArray : SkippingArray(related, skipping: skipped)
        }

        /// - Returns: The events kept by group and ``lookup`` value, or `nil` if a value can't be looked up by.
        private func makeIndex() -> [Pair: [PredicateRecord]]? {
            guard let lookup else { return nil }
            var index: [Pair: [PredicateRecord]] = [:]
            for (group, records) in kept {
                for record in records {
                    guard let value = record.value(forKeyPath: lookup.path), !(value is NSNull) else { continue }
                    guard let value = PredicateRelation.hashable(value) else { return nil }
                    index[Pair(group: group, value: value), default: []].append(record)
                }
            }
            return index
        }

        /// - Parameters:
        ///   - predicate: One of the conditions on both events.
        ///   - variable: The variable's name.
        /// - Returns: `path` and `expression` for `$e.path == expression`, or the same the other way round.
        private static func lookup(in predicate: NSPredicate, _ variable: String) -> (String, NSExpression)? {
            guard let comparison = predicate as? NSComparisonPredicate, comparison.predicateOperatorType == .equalTo,
                  comparison.comparisonPredicateModifier == .direct, comparison.options.isEmpty else { return nil }
            for (related, searched) in [(comparison.leftExpression, comparison.rightExpression),
                                        (comparison.rightExpression, comparison.leftExpression)] {
                if let path = related.keyPath(of: variable),
                   !searched.contains(where: { $0.expressionType == .variable }) { return (path, searched) }
            }
            return nil
        }

        /// - Parameter predicate: One of a `SUBQUERY`'s conditions.
        /// - Returns: Does it read the searched event, with a plain key path or `SELF`?
        private static func readsSearched(_ predicate: NSPredicate) -> Bool {
            predicate.contains { $0.expressionType == .keyPath || $0.expressionType == .evaluatedObject }
        }
    }
}


// MARK: - Same event
/// Which of a group's kept events are which event (``PredicateRecord/isSame(as:)``): by their storage, and by their
/// type, sequence number and time, compared as `isEqual(_:)` compares them.
struct Sameness {
    /// An event's type, sequence number and time, if it has all three (`null` counts).
    struct Identity: Hashable {
        let values: [NSObject]
        
        /// - Parameter record: An event's record.
        init?(_ record: NSDictionary) {
            var values: [NSObject] = []
            for key in PredicateRecord.identityKeys {
                guard let value = record[key] as? NSObject else { return nil }
                values.append(value)
            }
            self.values = values
        }
    }
    
    private var byStorage: [ObjectIdentifier: [Int]] = [:]
    private var byIdentity: [Identity: [Int]] = [:]
    
    /// - Parameter records: A group's events, in order.
    init(_ records: [PredicateRecord]) {
        for (index, record) in records.enumerated() {
            byStorage[ObjectIdentifier(record.values), default: []].append(index)
            if let identity = Identity(record.values) { byIdentity[identity, default: []].append(index) }
        }
    }
    
    /// - Parameter searched: The searched event.
    /// - Returns: The indexes of the group's events that are the same event, ascending.
    func indexes(of searched: PredicateRecord) -> [Int] {
        let identical = Identity(searched.values).flatMap { byIdentity[$0] } ?? []
        return Set(identical + (byStorage[ObjectIdentifier(searched.values)] ?? [])).sorted()
    }
}


/// Records without some of them, read in place, as `NSPredicate` reads a `SUBQUERY`'s related events.
final class SkippingArray: NSArray {
    private var records: [PredicateRecord] = []
    /// The indexes left out, ascending.
    private var skipped: [Int] = []
    
    /// - Parameters:
    ///   - records: The records.
    ///   - skipped: The indexes left out, ascending.
    convenience init(_ records: [PredicateRecord], skipping skipped: [Int]) {
        self.init()
        self.records = records
        self.skipped = skipped
    }
    
    override init() { super.init() }
    override init(objects: UnsafePointer<AnyObject>?, count: Int) { super.init(objects: objects, count: count) }
    required init?(coder: NSCoder) { nil }
    
    override var count: Int { records.count - skipped.count }
    
    /// - Parameter index: A position among the records left in.
    /// - Returns: The record there.
    override func object(at index: Int) -> Any {
        var position = index
        for skip in skipped where skip <= position { position += 1 }
        return records[position]
    }
}


extension PredicateRecord {
    /// The keys that tell one event from another (``isSame(as:)``).
    static let identityKeys = ["mach_time", "global_seq_num", "es_event_type"]

    /// Is this the same event as another, by its type, sequence number and time? A searched event isn't related to
    /// itself.
    ///
    /// - Parameter other: Another record.
    /// - Returns: `true` if both have the same `es_event_type`, `global_seq_num` and `mach_time`.
    func isSame(as other: PredicateRecord) -> Bool {
        values === other.values || Sameness.Identity(values).map { $0 == Sameness.Identity(other.values) } ?? false
    }
}
