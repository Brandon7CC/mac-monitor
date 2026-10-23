//
//  StreamFilter+Store.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/25/26.
//

import Foundation


// MARK: - Narrowing by the store
public extension StreamFilter.Predicate {
    /// A predicate on the event store's own columns that every event this predicate matches matches too, or `nil` when
    /// none can be said: `process.executable.path ENDSWITH "/curl"` narrows to `initiating_path ENDSWITH "/curl"`.
    ///
    /// The search reads and encodes each candidate event's record, about as slow as exporting it. SQLite narrows the
    /// candidates first, by these columns, so a search reads only the events that might match. The events it keeps are
    /// still checked against the predicate, so narrowing can only ever leave out events that couldn't match.
    var storePredicate: NSPredicate? {
        StoreNarrowing.predicate(for: parsed)
    }

    /// What the store can narrow the events a `SUBQUERY` collects (``collect(_:)``) to, from its conditions on the
    /// related event alone, or `nil` to collect from every event: `SUBQUERY(correlated, $e, $e.target_path CONTAINS
    /// "x").@count > 0` collects only from events whose `target_path` contains "x".
    var relatedStorePredicate: NSPredicate? {
        related.storePredicate
    }
}


// MARK: - Columns
/// Which of a record's values an ``ESMessage`` column holds, and the comparisons SQLite can make on them.
enum StoreNarrowing {
    /// A column and the type its values are.
    struct Column {
        let name: String
        let isText: Bool
    }

    /// Each record key path a column holds the value of whenever the record has one: the event's own values, and the
    /// copies of the instigating and created processes' (``ESMessage/denormalize(from:)``). `StoreNarrowingTests`
    /// checks it for every event the synthetic corpus and the fixtures have.
    static let columns: [String: Column] = {
        let text = [
            "es_event_type": "es_event_type", "context": "context", "target_path": "target_path", "time": "time",
            "action_type_string": "action_type_string", "macOS": "macOS", "sip_status": "sip_status",
            "sensor_id": "sensor_id",
            "process.executable.path": "initiating_path", "process.executable.name": "initiating_name",
            "process.signing_id": "initiating_signing_id", "process.euid_human": "initiating_euid_human",
            "process.audit_token_string": "instigator_audit_token",
            "event.exec.target.executable.path": "created_path", "event.fork.child.executable.path": "created_path",
            "event.exec.target.executable.name": "created_name", "event.fork.child.executable.name": "created_name",
            "event.exec.target.signing_id": "created_signing_id", "event.exec.command_line": "exec_command_line",
            "event.exec.target.audit_token_string": "created_audit_token",
            "event.fork.child.audit_token_string": "created_audit_token",
        ]
        let numbers = [
            "event_type": "event_type", "action_type": "action_type", "mach_time": "mach_time",
            "seq_num": "seq_num", "global_seq_num": "global_seq_num", "version": "version",
            "process.pid": "initiating_pid", "process.ppid": "initiating_ppid",
            "event.exec.target.pid": "created_pid", "event.fork.child.pid": "created_pid",
            "event.exec.target.group_id": "exec_group_id", "event.exec.target.session_id": "exec_session_id",
        ]
        return text.mapValues { Column(name: $0, isText: true) }
            .merging(numbers.mapValues { Column(name: $0, isText: false) }) { $1 }
    }()

    /// The comparisons SQLite makes as `NSPredicate` does, on a value the record has. Not `!=`, which a missing value
    /// passes in a record but not in a column, and not `MATCHES`, which SQLite would match without a time limit.
    private static let operators: Set<NSComparisonPredicate.Operator> = [
        .equalTo, .lessThan, .lessThanOrEqualTo, .greaterThan, .greaterThanOrEqualTo, .beginsWith, .endsWith,
        .contains, .like, .in,
    ]

    /// - Parameters:
    ///   - predicate: A predicate ``PredicateGuard`` passed.
    ///   - variable: A `SUBQUERY`'s variable, whose key paths (`$e.path`) the conditions name, or `nil` for plain ones.
    /// - Returns: What the store can narrow by for it, or `nil`.
    static func predicate(for predicate: NSPredicate, variable: String? = nil) -> NSPredicate? {
        switch predicate {
        case let compound as NSCompoundPredicate:
            let parts = compound.subpredicates.compactMap { $0 as? NSPredicate }
            switch compound.compoundPredicateType {
            /// Any part an event must pass.
            case .and:
                let narrowed = parts.compactMap { Self.predicate(for: $0, variable: variable) }
                return narrowed.isEmpty ? nil : NSCompoundPredicate(andPredicateWithSubpredicates: narrowed)
            /// Every part, or nothing: an event may pass the one that can't be said.
            case .or:
                let narrowed = parts.compactMap { Self.predicate(for: $0, variable: variable) }
                return narrowed.count == parts.count ? NSCompoundPredicate(orPredicateWithSubpredicates: narrowed) : nil
            default:
                return nil
            }
        case let comparison as NSComparisonPredicate:
            return narrowed(comparison, variable)
        default:
            return nil
        }
    }

    /// - Parameters:
    ///   - comparison: A comparison.
    ///   - variable: A `SUBQUERY`'s variable, or `nil`.
    /// - Returns: The same comparison on a column, for `keyPath <op> constant` on a key path a column holds.
    private static func narrowed(_ comparison: NSComparisonPredicate, _ variable: String?) -> NSPredicate? {
        guard comparison.comparisonPredicateModifier == .direct,
              operators.contains(comparison.predicateOperatorType),
              let path = keyPath(of: comparison.leftExpression, variable),
              let column = columns[path],
              let constant = constant(of: comparison.rightExpression),
              fits(constant, column, comparison.predicateOperatorType) else { return nil }
        return NSComparisonPredicate(leftExpression: NSExpression(forKeyPath: column.name),
                                     rightExpression: comparison.rightExpression,
                                     modifier: .direct, type: comparison.predicateOperatorType,
                                     options: comparison.options)
    }

    /// - Parameters:
    ///   - expression: A comparison's left side.
    ///   - variable: A `SUBQUERY`'s variable, or `nil`.
    /// - Returns: The key path it reads: `path` for `path` without a variable, or for `$e.path` with one.
    private static func keyPath(of expression: NSExpression, _ variable: String?) -> String? {
        guard let variable else { return expression.expressionType == .keyPath ? expression.keyPath : nil }
        guard expression.expressionType == .function, expression.function == "valueForKeyPath:",
              expression.operand.expressionType == .variable, expression.operand.variable == variable else {
            return nil
        }
        return expression.arguments?.first?.keyPath
    }

    /// - Parameter expression: A comparison's right side.
    /// - Returns: Its constant, or for `IN {…}` its constants, or `nil` for anything read from the record.
    private static func constant(of expression: NSExpression) -> Any? {
        switch expression.expressionType {
        case .constantValue:
            return expression.constantValue
        case .aggregate:
            let members = (expression.collection as? [NSExpression]) ?? []
            guard members.allSatisfy({ $0.expressionType == .constantValue }) else { return nil }
            return members.compactMap(\.constantValue) as NSArray
        default:
            return nil
        }
    }

    /// Is a constant the column's type, so SQLite compares it as the record would? `IN` takes a collection of them.
    ///
    /// - Parameters:
    ///   - constant: The comparison's constant.
    ///   - column: The column.
    ///   - type: The comparison.
    /// - Returns: `true` if every value is a string for text, or a number for numbers.
    private static func fits(_ constant: Any, _ column: Column, _ type: NSComparisonPredicate.Operator) -> Bool {
        let values: [Any]
        if type == .in {
            switch constant {
            case let array as NSArray: values = array as [AnyObject]
            case let set as NSSet: values = set.allObjects
            default: return false
            }
            guard !values.isEmpty else { return false }
        } else {
            values = [constant]
        }
        let textOnly: Set<NSComparisonPredicate.Operator> = [.beginsWith, .endsWith, .contains, .like]
        guard column.isText || !textOnly.contains(type) else { return false }
        return values.allSatisfy { column.isText ? $0 is NSString : ($0 is NSNumber && !($0 is NSString)) }
    }
}
