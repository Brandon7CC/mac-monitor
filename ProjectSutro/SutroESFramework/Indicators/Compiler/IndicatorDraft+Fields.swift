//
//  IndicatorDraft+Fields.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Comparing two fields
extension IndicatorDraft {
    /// A field compared with another field of the same event, as in `event.exec.target.team_id != process.team_id`.
    ///
    /// What it takes, checked as it's read (``init(_:)``), the same rules whether ``IndicatorCompiler`` or Mac
    /// Monitor's own check of an indicator's predicate (``StreamFilter/Predicate``) reads it:
    ///
    /// - `==`, `!=`, `<`, `<=`, `>`, `>=`, `BEGINSWITH` and `ENDSWITH`, with no `ANY` or `ALL`. `CONTAINS`, `LIKE`,
    ///   `IN` and `MATCHES` take constants alone.
    /// - Two key paths the Security Extension reads (``IndicatorField``): none Mac Monitor writes as it stores the
    ///   event, on either side.
    /// - Two of the same kind in the telemetry schema: two strings, or two numbers, a Boolean counting as one. Never
    ///   an array, which `ANY` compares with constants alone.
    /// - Strings aren't ordered, and `[c]` and `[d]` compare strings alone, as with constants.
    ///
    /// It's evaluated as `NSPredicate` evaluates it on the record (`IndicatorProgram+Fields.swift`).
    struct FieldComparison: Equatable {
        /// The left side's field.
        let left: IndicatorField
        /// The operator.
        let op: IndicatorProgram.Operator
        /// Its options.
        let options: IndicatorProgram.Options
        /// The right side's field.
        let right: IndicatorField

        /// The operators a field compared with a field takes.
        static let operators: [IndicatorProgram.Operator] = [.equalTo, .notEqualTo, .lessThan, .lessThanOrEqualTo,
                                                              .greaterThan, .greaterThanOrEqualTo, .beginsWith,
                                                              .endsWith]
        /// The ordering operators, which compare numbers alone.
        static let ordering: [IndicatorProgram.Operator] = [.lessThan, .lessThanOrEqualTo, .greaterThan,
                                                             .greaterThanOrEqualTo]

        /// Read a comparison whose right side is a key path.
        ///
        /// - Parameter comparison: The comparison, with a key path on its right.
        /// - Throws: ``SensorProblem`` for the first rule it breaks.
        init(_ comparison: NSComparisonPredicate) throws(SensorProblem) {
            let part = Part(comparison: comparison)
            if comparison.comparisonPredicateModifier != .direct {
                let modifier = comparison.comparisonPredicateModifier == .any ? "ANY" : "ALL"
                throw .unsupported("\(modifier) with a key path on its right, in \(part): \(modifier) compares an "
                                   + "array's strings with constants alone")
            }
            let op: IndicatorProgram.Operator
            do {
                op = try Builder.operator(of: comparison)
            } catch {
                throw .unsupported("\(Self.name(of: comparison)) with a key path on its right, in \(part): a key "
                                   + "path compared with another takes \(Self.allowed)")
            }
            guard Self.operators.contains(op) else {
                throw .unsupported("\(IndicatorProgram.symbol(of: op)) with a key path on its right, in \(part): a "
                                   + "key path compared with another takes \(Self.allowed)")
            }
            let options = try Self.options(of: comparison)
            guard comparison.leftExpression.expressionType == .keyPath else {
                throw .unsupported("\(comparison.leftExpression), in \(part)")
            }
            let left = try Builder.field(at: comparison.leftExpression.keyPath)
            let right = try Builder.field(at: comparison.rightExpression.keyPath)
            try Self.check(left, op, options, right, part: part)
            self.init(left: left, op: op, options: options, right: right)
        }

        /// - Parameters:
        ///   - left: The left side's field.
        ///   - op: The operator.
        ///   - options: Its options.
        ///   - right: The right side's field.
        init(left: IndicatorField, op: IndicatorProgram.Operator, options: IndicatorProgram.Options,
             right: IndicatorField) {
            self.left = left
            self.op = op
            self.options = options
            self.right = right
        }

        /// The operators as a refusal lists them: "==, !=, <, <=, >, >=, BEGINSWITH or ENDSWITH".
        static let allowed = operators.dropLast().map(IndicatorProgram.symbol(of:)).joined(separator: ", ")
            + " or " + IndicatorProgram.symbol(of: operators[operators.count - 1])

        /// - Parameter comparison: A comparison.
        /// - Returns: Its operator as a predicate writes it, for one ``IndicatorProgram/Operator`` has no case for.
        private static func name(of comparison: NSComparisonPredicate) -> String {
            switch comparison.predicateOperatorType {
            case .matches: "MATCHES"
            case .between: "BETWEEN"
            default: "its operator"
            }
        }

        /// - Parameter comparison: A comparison.
        /// - Returns: Its options.
        /// - Throws: ``SensorProblem`` for any but `[c]` and `[d]`.
        private static func options(of comparison: NSComparisonPredicate) throws(SensorProblem)
            -> IndicatorProgram.Options {
            do {
                return try Builder.options(of: comparison)
            } catch let problem as SensorProblem {
                throw problem
            } catch {
                throw .unsupported(comparison.predicateFormat)
            }
        }

        /// Refuse two fields that aren't of one kind, or that the operator and options can't compare.
        ///
        /// - Parameters:
        ///   - left: The left side's field.
        ///   - op: The operator.
        ///   - options: Its options.
        ///   - right: The right side's field.
        ///   - part: The comparison, for a problem.
        /// - Throws: ``SensorProblem`` when it's refused.
        private static func check(_ left: IndicatorField, _ op: IndicatorProgram.Operator,
                                  _ options: IndicatorProgram.Options, _ right: IndicatorField,
                                  part: Part) throws(SensorProblem) {
            for field in [left, right] where field.kind == .strings {
                throw .mismatchedTypes("\(field.path) is an array, which ANY compares with constants alone, not "
                                       + "with a key path, in \(part)")
            }
            let isString = left.kind == .string
            guard isString == (right.kind == .string) else {
                throw .mismatchedTypes("\(left.path) is \(Self.name(of: left.kind)) and \(right.path) "
                                       + "\(Self.name(of: right.kind)), in \(part)")
            }
            if isString, ordering.contains(op) { throw .unsupported("ordering strings, in \(part)") }
            if !isString, op == .beginsWith || op == .endsWith { throw .mismatchedTypes(part.description) }
            if !isString, !options.isEmpty { throw .unsupported("[c] or [d] on a number, in \(part)") }
        }

        /// - Parameter kind: A field's kind.
        /// - Returns: It as a refusal names it: "a string", "a number" or "a Boolean".
        private static func name(of kind: IndicatorField.Kind) -> String {
            switch kind {
            case .string: "a string"
            case .number: "a number"
            case .boolean: "a Boolean"
            case .strings: "an array"
            }
        }
    }

    /// Check every comparison of two key paths in a predicate by ``FieldComparison``'s rules, as the Security
    /// Extension reads it, so Mac Monitor's own check of an indicator refuses exactly the field comparisons the
    /// compiler does, in the same words. Any other part is left to the caller.
    ///
    /// - Parameter predicate: A parsed predicate.
    /// - Throws: ``SensorProblem`` for the first field comparison refused.
    static func checkFieldComparisons(in predicate: NSPredicate) throws(SensorProblem) {
        switch predicate {
        case let compound as NSCompoundPredicate:
            for case let part as NSPredicate in compound.subpredicates { try checkFieldComparisons(in: part) }
        case let comparison as NSComparisonPredicate where comparison.rightExpression.expressionType == .keyPath:
            _ = try FieldComparison(comparison)
        default:
            return
        }
    }
}
