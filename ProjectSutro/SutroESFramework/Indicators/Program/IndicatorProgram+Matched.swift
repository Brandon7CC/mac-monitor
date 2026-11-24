//
//  IndicatorProgram+Matched.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation


// MARK: - What a program matched
extension IndicatorProgram.View {
    /// The comparisons that made a matching program match, each with the value the event had: what a hit lists
    /// (``IndicatorHit/matched``).
    ///
    /// It walks the program once more, only for a rule that already matched, so a rule that doesn't costs nothing
    /// more. An `AND` lists what each of its children matched. An `OR` lists its first child that matched, the one
    /// that decided it. Nothing under a `NOT` is listed, nor a `!=` a value: they say what the event doesn't have.
    /// `!= nil` is listed, as it says the event has a value. `ANY` lists the string of the array that decided it,
    /// and a comparison of two fields lists both.
    ///
    /// - Parameters:
    ///   - root: The program's root node.
    ///   - message: The event, which the program matched.
    ///   - eventType: Its type's number.
    ///   - values: The lane's values for this event. What the walk reads spends from their budget.
    ///   - fields: What it matched is added here, each once, up to ``IndicatorMatchedField/limit``.
    func matched(root: Int, _ message: borrowing Message, eventType: Int, values: inout MessageValueCache,
                 into fields: inout [IndicatorMatchedField]) {
        _ = collect(root, message, eventType, &values, into: &fields)
    }

    /// - Parameters:
    ///   - index: A node's index.
    ///   - message: The event.
    ///   - eventType: Its type's number.
    ///   - values: The lane's values for this event.
    ///   - fields: What the node matched is added here when its verdict is `yes`.
    /// - Returns: The node's verdict.
    private func collect(_ index: Int, _ message: borrowing Message, _ eventType: Int,
                         _ values: inout MessageValueCache,
                         into fields: inout [IndicatorMatchedField]) -> IndicatorVerdict {
        let node = nodes[index], mark = fields.count
        switch node.kind {
        case .and:
            var verdict = IndicatorVerdict.yes
            for child in node.range {
                switch collect(child, message, eventType, &values, into: &fields) {
                case .yes:
                    continue
                case .unknown:
                    verdict = .unknown
                case .no:
                    fields.removeSubrange(mark...)
                    return .no
                }
            }
            return verdict
        case .or:
            var verdict = IndicatorVerdict.no
            for child in node.range {
                let before = fields.count
                let child = collect(child, message, eventType, &values, into: &fields)
                if child == .yes { return .yes }
                fields.removeSubrange(before...)
                if child == .unknown { verdict = .unknown }
            }
            return verdict
        case .not, .truth, .eventType:
            /// Nothing under a `NOT` is listed, so it's only decided.
            return evaluate(index, message, eventType, &values)
        case .compare:
            let verdict = evaluate(index, message, eventType, &values)
            /// `!= nil` says the event has a value there. Any other `!=` says what it isn't.
            guard verdict == .yes, node.op != .notEqualTo || constants[Int(node.first)].kind == .null else {
                return verdict
            }
            note(node.field, values.value(of: node.field, in: message), in: &fields)
            return verdict
        case .fieldCompare:
            let verdict = evaluate(index, message, eventType, &values)
            guard verdict == .yes, node.op != .notEqualTo else { return verdict }
            for field in [node.field, node.other] {
                note(field, values.value(of: field, in: message), in: &fields)
            }
            return verdict
        case .anyCompare:
            /// `ANY ... !=` says what one of them isn't.
            guard node.op != .notEqualTo,
                  case .strings(let elements) = values.value(of: node.field, in: message) else {
                return evaluate(index, message, eventType, &values)
            }
            /// As `ANY` itself decides, within what's left of the allowance: it says which string matched.
            var found = -1
            let verdict = any(node, elements, &values, found: &found)
            if verdict == .yes, elements.indices.contains(found) {
                note(node.field, .string(elements[found][...]), in: &fields)
            }
            return verdict
        }
    }

    /// Add a field and the value the event had there, once, while there's room. A field with no value isn't added.
    ///
    /// - Parameters:
    ///   - field: The field a comparison read.
    ///   - value: The event's value.
    ///   - fields: What's matched so far.
    private func note(_ field: IndicatorField, _ value: IndicatorValue, in fields: inout [IndicatorMatchedField]) {
        guard fields.count < IndicatorMatchedField.limit,
              let value = IndicatorMatchedField.Value(value, kind: field.kind) else { return }
        let matched = IndicatorMatchedField(field: field.path, value: value)
        if !fields.contains(matched) { fields.append(matched) }
    }
}
