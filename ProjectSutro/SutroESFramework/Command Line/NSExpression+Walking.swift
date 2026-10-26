//
//  NSExpression+Walking.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation


// MARK: - Walking expressions
extension NSExpression {
    /// The expressions it reads to get its value: a function's operand and arguments, an aggregate's members, a set
    /// operation's sides. `$e.path`'s and `SUBQUERY(…).@count`'s key path is a name, read from nothing, and a
    /// `SUBQUERY`'s conditions read its own variable, so neither is one.
    var subexpressions: [NSExpression] {
        switch expressionType {
        case .function where function == "valueForKeyPath:": return [operand]
        case .function: return [operand] + (arguments ?? [])
        case .aggregate: return collection as? [NSExpression] ?? []
        case .unionSet, .intersectSet, .minusSet: return [left, right]
        default: return []
        }
    }

    /// - Parameter test: A test of one expression.
    /// - Returns: Does it pass for this expression, or for one it reads, at any depth?
    func contains(where test: (NSExpression) -> Bool) -> Bool {
        test(self) || subexpressions.contains { $0.contains(where: test) }
    }

    /// - Parameter variable: A `SUBQUERY`'s variable's name.
    /// - Returns: `path` for `$variable.path`, else `nil`.
    func keyPath(of variable: String) -> String? {
        guard expressionType == .function, function == "valueForKeyPath:", operand.expressionType == .variable,
              operand.variable == variable else { return nil }
        return arguments?.first?.keyPath
    }
}


// MARK: - Walking predicates
extension NSPredicate {
    /// - Parameter test: A test of one expression.
    /// - Returns: Does it pass for an expression one of its comparisons reads, at any depth?
    func contains(where test: (NSExpression) -> Bool) -> Bool {
        switch self {
        case let compound as NSCompoundPredicate:
            return compound.subpredicates.contains { ($0 as? NSPredicate)?.contains(where: test) ?? false }
        case let comparison as NSComparisonPredicate:
            return comparison.leftExpression.contains(where: test) || comparison.rightExpression.contains(where: test)
        default:
            return false
        }
    }
}
