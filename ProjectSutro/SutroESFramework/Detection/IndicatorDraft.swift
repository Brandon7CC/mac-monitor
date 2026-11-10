//
//  IndicatorDraft.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
import EndpointSecurity


// MARK: - Drafts
/// A predicate as ``IndicatorCompiler`` reads it, before it's laid out as an ``IndicatorProgram``: a tree of the
/// parts the Security Extension evaluates, each checked as it's read.
indirect enum IndicatorDraft: Equatable {
    /// True when every child is.
    case and([IndicatorDraft])
    /// True when any child is.
    case or([IndicatorDraft])
    /// True when its child isn't.
    case not(IndicatorDraft)
    /// `TRUEPREDICATE` or `FALSEPREDICATE`.
    case truth(Bool)
    /// A field compared with constants.
    case compare(Comparison)
    /// The event's type `==`, `!=` or `IN` these, by number.
    case eventType(IndicatorProgram.Operator, [Int])

    /// A field compared with constants.
    struct Comparison: Equatable {
        /// The field.
        let field: IndicatorField
        /// The operator.
        let op: IndicatorProgram.Operator
        /// Its options.
        let options: IndicatorProgram.Options
        /// `ANY` of an array's values?
        let isAny: Bool
        /// One constant, a set for `IN`, or a `LIKE` pattern.
        let constants: [Constant]
    }

    /// A comparison's constant.
    enum Constant: Equatable {
        /// `nil`.
        case null
        /// A string, in native UTF-8, and as the predicate holds it, for Foundation's comparisons.
        case string(String, NSString)
        /// A number, and whether it's whole.
        case number(Double, isInteger: Bool)
    }

    /// The same, with an `AND` inside an `AND`, or an `OR` inside an `OR`, made one: `(a AND b) AND c` is
    /// `a AND b AND c`. An `OR`'s type checks are one too, where the first was: `event.create != nil OR
    /// event.rename != nil` is `es_event_type IN` both, which a top-level `AND` then drops (``removingTypeChecks``).
    /// Each child is flattened once: twice doubled the work at every level of `AND`s and `OR`s nested in turn.
    var flattened: IndicatorDraft {
        switch self {
        case .and(let children):
            return .and(children.flatMap { child -> [IndicatorDraft] in
                let flat = child.flattened
                if case .and(let inner) = flat { return inner }
                return [flat]
            })
        case .or(let children):
            return Self.joiningTypeChecks(children.flatMap { child -> [IndicatorDraft] in
                let flat = child.flattened
                if case .or(let inner) = flat { return inner }
                return [flat]
            })
        case .not(let child):
            return .not(child.flattened)
        default:
            return self
        }
    }

    /// - Parameter children: An `OR`'s children, flattened.
    /// - Returns: The `OR`, its checks that an event is one of some types made one where the first was, or that
    ///   check alone when it's all the `OR` has.
    private static func joiningTypeChecks(_ children: [IndicatorDraft]) -> IndicatorDraft {
        var types: [Int] = [], first: Int?
        for (position, child) in children.enumerated() {
            guard case .eventType(let op, let checked) = child, op != .notEqualTo else { continue }
            types += checked
            first = first ?? position
        }
        guard let first, children.count > 1 else { return .or(children) }
        let unique = Array(Set(types)).sorted()
        let joined = IndicatorDraft.eventType(unique.count == 1 ? .equalTo : .in, unique)
        let rest = children.enumerated().compactMap { position, child -> IndicatorDraft? in
            if position == first { return joined }
            if case .eventType(let op, _) = child, op != .notEqualTo { return nil }
            return child
        }
        return rest.count == 1 ? rest[0] : .or(rest)
    }

    /// What reading a part's fields can cost an event, which orders an `AND`'s and an `OR`'s children
    /// (``readingCheapestFirst``).
    enum ReadCost: Int, CaseIterable, Comparable {
        /// Only fields that stay small, or none.
        case small
        /// `command_line`, `env` or `script_content`, which an event can make up to 1 MiB (``ScanPool/isLarge``): a
        /// search of one can spend its pool, and the index's, whole.
        case large
        /// A record field, which walks the event's encoding the first time one is read (``RecordPathTrie``).
        case record

        /// - Parameters:
        ///   - lhs: A cost.
        ///   - rhs: Another.
        /// - Returns: Is `lhs` the cheaper?
        static func < (lhs: ReadCost, rhs: ReadCost) -> Bool {
            lhs.rawValue < rhs.rawValue
        }
    }

    /// What reading its fields can cost an event: the costliest of its comparisons'.
    var readCost: ReadCost {
        switch self {
        case .and(let children), .or(let children): children.map(\.readCost).max() ?? .small
        case .not(let child): child.readCost
        case .compare(let comparison):
            !comparison.field.isDirect ? .record : comparison.field.scanPool.isLarge ? .large : .small
        case .truth, .eventType: .small
        }
    }

    /// The same, with each `AND`'s and `OR`'s children ordered by what reading them can cost (``ReadCost``): those
    /// that read only small fields first, then those that read a large one, then those that read a record field. So a
    /// cheap child decides it first: a target's path rules out an exec before its 1 MiB command line is searched, and
    /// most events are never walked. On a cost tie, the index anchors an `AND` on its first cheapest child
    /// (``IndicatorProgram/View/necessity(root:eventType:)``), so a small field's literal is checked rather than a
    /// large one's. A verdict doesn't depend on its children's order (``IndicatorProgram/View``), so no verdict
    /// changes, save which comparison a spent scan budget refuses.
    var readingCheapestFirst: IndicatorDraft {
        /// - Parameter children: An `AND`'s or an `OR`'s children.
        /// - Returns: The same, each reordered within, by their cost and, at the same cost, in their order.
        func cheapestFirst(_ children: [IndicatorDraft]) -> [IndicatorDraft] {
            let ordered = children.map(\.readingCheapestFirst)
            return ReadCost.allCases.flatMap { cost in ordered.filter { $0.readCost == cost } }
        }
        return switch self {
        case .and(let children): .and(cheapestFirst(children))
        case .or(let children): .or(cheapestFirst(children))
        case .not(let child): .not(child.readingCheapestFirst)
        default: self
        }
    }

    /// The same, without the type checks every event it runs on passes: a top-level `AND`'s, or the whole rule's.
    /// One anywhere else stays.
    ///
    /// - Parameter types: The types the rule runs on.
    /// - Returns: The draft, `TRUEPREDICATE` when nothing's left.
    func removingTypeChecks(passedBy types: Set<Int>) -> IndicatorDraft {
        /// - Parameter draft: A part of the rule.
        /// - Returns: Is it a type check every event the rule runs on passes?
        func isPassed(_ draft: IndicatorDraft) -> Bool {
            guard case .eventType(let op, let checked) = draft, op != .notEqualTo else { return false }
            return types.isSubset(of: checked)
        }
        if isPassed(self) { return .truth(true) }
        guard case .and(let children) = self else { return self }
        let kept = children.filter { !isPassed($0) }
        return kept.isEmpty ? .truth(true) : kept.count == 1 ? kept[0] : .and(kept)
    }
}


// MARK: - Reading a predicate
extension IndicatorDraft {
    /// A comparison as a problem names it, written only when there's a problem: writing a predicate's format costs
    /// more than reading it.
    struct Part: CustomStringConvertible {
        /// The comparison.
        let comparison: NSComparisonPredicate

        /// The comparison as `NSPredicate` writes it.
        var description: String { comparison.predicateFormat }
    }

    /// Reads a parsed predicate into a draft, counting its nodes.
    struct Builder {
        /// The nodes read so far.
        private(set) var nodes = 0
        /// Each direct field by its key path, as Foundation holds strings, so the parsed key paths aren't bridged to
        /// look up. Any other key path is a record field (``IndicatorField/record(_:)``).
        private static let fields = Dictionary(uniqueKeysWithValues: IndicatorField.allCases.map {
            (NSString(string: $0.path), $0)
        })

        /// - Parameter predicate: A parsed predicate, or a part of one.
        /// - Returns: Its draft.
        /// - Throws: ``SensorProblem`` for the first part the Security Extension can't evaluate.
        mutating func draft(_ predicate: NSPredicate) throws -> IndicatorDraft {
            nodes += 1
            guard nodes <= IndicatorCompiler.maxNodes else { throw SensorProblem.tooManyNodes }
            switch predicate {
            case let compound as NSCompoundPredicate:
                var parts: [IndicatorDraft] = []
                for case let part as NSPredicate in compound.subpredicates { parts.append(try draft(part)) }
                switch compound.compoundPredicateType {
                case .and: return .and(parts)
                case .or: return .or(parts)
                case .not where parts.count == 1: return .not(parts[0])
                default: throw SensorProblem.unsupported(compound.predicateFormat)
                }
            case let comparison as NSComparisonPredicate:
                return try draft(comparison)
            default:
                switch predicate.predicateFormat {
                case "TRUEPREDICATE": return .truth(true)
                case "FALSEPREDICATE": return .truth(false)
                default: throw SensorProblem.unsupported(predicate.predicateFormat)
                }
            }
        }

        /// - Parameter comparison: A comparison.
        /// - Returns: Its draft: a comparison of a field, or of the event's type.
        /// - Throws: ``SensorProblem`` when the Security Extension can't evaluate it.
        private func draft(_ comparison: NSComparisonPredicate) throws -> IndicatorDraft {
            if let test = PredicateEventTypes.payloadTest(comparison) {
                let type = Int(eventStringToType(from: test.name).rawValue)
                return .eventType(test.isPresent ? .equalTo : .notEqualTo, [type])
            }
            let part = Part(comparison: comparison)
            let isAny: Bool
            switch comparison.comparisonPredicateModifier {
            case .direct: isAny = false
            case .any: isAny = true
            default: throw SensorProblem.unsupported("ALL, in \(part)")
            }
            let op = try Self.operator(of: comparison)
            let options = try Self.options(of: comparison)
            let left = comparison.leftExpression
            guard left.expressionType == .keyPath else { throw SensorProblem.unsupported("\(left), in \(part)") }
            let field = try Self.fields[left.keyPath as NSString] ?? IndicatorField.record(left.keyPath)
            let constants = try Self.constants(of: comparison.rightExpression, isSet: op == .in, part: part)
            if field == .esEventType, !isAny, options.isEmpty, [.equalTo, .notEqualTo, .in].contains(op),
               let types = Self.eventTypes(constants) {
                return .eventType(op, types)
            }
            try Self.check(field, op, options, isAny: isAny, constants, part: part)
            return .compare(Comparison(field: field, op: op, options: options, isAny: isAny, constants: constants))
        }

        /// - Parameter comparison: A comparison.
        /// - Returns: Its operator.
        /// - Throws: ``SensorProblem`` for `MATCHES`, `BETWEEN` and a custom selector.
        private static func `operator`(of comparison: NSComparisonPredicate) throws -> IndicatorProgram.Operator {
            switch comparison.predicateOperatorType {
            case .equalTo: return .equalTo
            case .notEqualTo: return .notEqualTo
            case .lessThan: return .lessThan
            case .lessThanOrEqualTo: return .lessThanOrEqualTo
            case .greaterThan: return .greaterThan
            case .greaterThanOrEqualTo: return .greaterThanOrEqualTo
            case .in: return .in
            case .beginsWith: return .beginsWith
            case .endsWith: return .endsWith
            case .contains: return .contains
            case .like: return .like
            case .matches: throw SensorProblem.unsupported("MATCHES, in \(comparison.predicateFormat)")
            case .between: throw SensorProblem.unsupported("BETWEEN, in \(comparison.predicateFormat)")
            default: throw SensorProblem.unsupported(comparison.predicateFormat)
            }
        }

        /// - Parameter comparison: A comparison.
        /// - Returns: Its options.
        /// - Throws: ``SensorProblem`` for any but `[c]` and `[d]`.
        private static func options(of comparison: NSComparisonPredicate) throws -> IndicatorProgram.Options {
            let known: NSComparisonPredicate.Options = [.caseInsensitive, .diacriticInsensitive]
            guard comparison.options.isSubset(of: known) else {
                throw SensorProblem.unsupported("options other than [c] and [d], in \(comparison.predicateFormat)")
            }
            var options: IndicatorProgram.Options = []
            if comparison.options.contains(.caseInsensitive) { options.insert(.caseInsensitive) }
            if comparison.options.contains(.diacriticInsensitive) { options.insert(.diacriticInsensitive) }
            return options
        }

        /// - Parameters:
        ///   - expression: A comparison's right side.
        ///   - isSet: Is it `IN`'s, which takes a set?
        ///   - part: The comparison, for a problem.
        /// - Returns: Its constants.
        /// - Throws: ``SensorProblem`` for anything but a constant, or a set of them for `IN`.
        private static func constants(of expression: NSExpression, isSet: Bool, part: Part) throws -> [Constant] {
            let objects: [Any?]
            switch expression.expressionType {
            case .constantValue where isSet:
                guard let array = (expression.constantValue as? NSArray).map(Array.init)
                        ?? (expression.constantValue as? NSSet)?.allObjects else {
                    throw SensorProblem.unsupported("IN without a set, in \(part)")
                }
                objects = array
            case .constantValue:
                objects = [expression.constantValue]
            case .aggregate where isSet:
                guard let members = expression.constantMembers else {
                    throw SensorProblem.unsupported("a set of other than constants, in \(part)")
                }
                objects = members
            default:
                throw SensorProblem.unsupported("\(expression), in \(part): it compares a field with constants")
            }
            return try objects.map { try constant($0, part: part) }
        }

        /// - Parameters:
        ///   - object: A constant, as `NSPredicate` parsed it.
        ///   - part: The comparison, for a problem.
        /// - Returns: The constant.
        /// - Throws: ``SensorProblem`` for anything but `nil`, a string or a number, a string over
        ///   ``IndicatorCompiler/maxConstantBytes``, and a number that isn't whole within ±2^53 or finite.
        private static func constant(_ object: Any?, part: Part) throws -> Constant {
            switch object {
            case nil, is NSNull:
                return .null
            case let held as NSString:
                /// Read once as native UTF-8, rather than through the bridge at every look.
                var string = held as String
                string.makeContiguousUTF8()
                guard string.utf8.count <= IndicatorCompiler.maxConstantBytes else {
                    throw SensorProblem.constantTooLong(string.utf8.count)
                }
                return .string(string, held.copy() as? NSString ?? NSString(string: string))
            case let number as NSNumber where CFGetTypeID(number) == CFBooleanGetTypeID():
                return .number(number.boolValue ? 1 : 0, isInteger: true)
            case let number as NSNumber:
                let value = number.doubleValue
                guard value.isFinite else { throw SensorProblem.unrepresentableNumber(number.stringValue) }
                guard !["f", "d"].contains(String(cString: number.objCType)) else {
                    return .number(value, isInteger: false)
                }
                /// A whole number a `Double` holds exactly: 2^53 + 1 reads as 2^53.
                guard value.magnitude <= IndicatorCompiler.maxInteger, let integer = Int64(exactly: value),
                      NSNumber(value: integer).isEqual(to: number) else {
                    throw SensorProblem.unrepresentableNumber(number.stringValue)
                }
                return .number(value, isInteger: true)
            default:
                throw SensorProblem.unsupported("the constant \(String(describing: object)), in \(part)")
            }
        }

        /// - Parameter constants: An `es_event_type` comparison's constants.
        /// - Returns: The types they name, by number, when each is a type this build knows.
        private static func eventTypes(_ constants: [Constant]) -> [Int]? {
            let types = constants.map { constant -> Int? in
                guard case .string(let name, _) = constant else { return nil }
                let type = eventStringToType(from: name)
                return type == ES_EVENT_TYPE_LAST ? nil : Int(type.rawValue)
            }
            return types.contains(nil) ? nil : types.compactMap { $0 }
        }

        /// Refuse a comparison whose constants aren't of its field's kind, or that the kind can't take.
        ///
        /// - Parameters:
        ///   - field: The field.
        ///   - op: The operator.
        ///   - options: The options.
        ///   - isAny: Is it `ANY`?
        ///   - constants: The constants.
        ///   - part: The comparison, for a problem.
        /// - Throws: ``SensorProblem`` when it's refused.
        private static func check(_ field: IndicatorField, _ op: IndicatorProgram.Operator,
                                  _ options: IndicatorProgram.Options, isAny: Bool, _ constants: [Constant],
                                  part: Part) throws {
            switch (field.kind, isAny) {
            case (.strings, false):
                throw SensorProblem.mismatchedTypes("\(field.path) is an array, compared with ANY, in \(part)")
            case (.string, true), (.number, true), (.boolean, true):
                throw SensorProblem.unsupported("ANY of \(field.path), which isn't an array, in \(part)")
            default: break
            }
            let isString = field.kind == .string || field.kind == .strings
            for constant in constants {
                switch constant {
                case .null where op == .equalTo || op == .notEqualTo: break
                case .null: throw SensorProblem.unsupported("nil with \(IndicatorProgram.symbol(of: op)), in \(part)")
                case .string where !isString, .number where isString:
                    throw SensorProblem.mismatchedTypes(part.description)
                default: break
                }
            }
            let ordering: [IndicatorProgram.Operator] = [.lessThan, .lessThanOrEqualTo, .greaterThan,
                                                         .greaterThanOrEqualTo]
            if isString, ordering.contains(op) { throw SensorProblem.unsupported("ordering strings, in \(part)") }
            if !isString, [.beginsWith, .endsWith, .contains, .like].contains(op) {
                throw SensorProblem.mismatchedTypes(part.description)
            }
            if !isString, !options.isEmpty { throw SensorProblem.unsupported("[c] or [d] on a number, in \(part)") }
            if op == .like, case .string(let pattern, _) = constants.first,
               pattern.contains(where: { !$0.isASCII || $0 == "?" || $0 == "\\" }) {
                throw SensorProblem.unsupportedPattern(IndicatorValue.literal(pattern[...]))
            }
        }
    }
}
