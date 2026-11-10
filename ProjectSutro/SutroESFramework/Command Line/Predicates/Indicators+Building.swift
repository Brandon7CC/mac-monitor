//
//  Indicators+Building.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Building
extension Indicator {
    /// - Parameter number: A default's or a mark's number.
    /// - Returns: Its identity, the same on every Mac.
    static func uuid(_ number: Int) -> UUID {
        UUID(uuidString: shippedPrefix + String(format: "%012X", number))!
    }

    /// The start of every identity Mac Monitor gives an indicator or a mark it ships (``uuid(_:)``).
    private static let shippedPrefix = "6D4D0F1D-0000-4000-8000-"

    /// - Parameter id: An indicator's identity.
    /// - Returns: Is it one Mac Monitor ships, or shipped once? A number is never given to another indicator, so one a
    ///   later build drops is still known as Mac Monitor's.
    static func isShippedIdentity(_ id: UUID) -> Bool {
        id.uuidString.hasPrefix(shippedPrefix)
    }

    /// - Parameter types: Event types, without `ES_EVENT_TYPE_NOTIFY_`.
    /// - Returns: The test an event of one of them passes, its payload's (``PredicateEventTypes``), as in
    ///   `event.exit != nil`.
    static func type(_ types: String...) -> String {
        type(types)
    }

    /// - Parameter types: Event types, without `ES_EVENT_TYPE_NOTIFY_`.
    /// - Returns: The test an event of one of them passes, its payload's (``PredicateEventTypes``), as in
    ///   `event.exit != nil`, or `(event.create != nil OR event.rename != nil)` for more than one.
    static func type(_ types: [String]) -> String {
        let tests = types.map { "event.\($0.lowercased()) != nil" }
        return tests.count == 1 ? tests[0] : "(" + tests.joined(separator: " OR ") + ")"
    }

    /// A built-in mark. It marks the tables only.
    ///
    /// - Parameters:
    ///   - number: Its number.
    ///   - name: What it's called.
    ///   - description: Its help. An empty one shows none.
    ///   - symbol: Its SF Symbol.
    ///   - color: Its color.
    ///   - predicate: The predicate an event matches.
    /// - Returns: The mark.
    static func mark(_ number: Int, _ name: String, _ description: String, symbol: String, color: Color = .primary,
                     predicate: String) -> Indicator {
        Indicator(id: uuid(number), name: name, description: description, symbol: symbol, color: color,
                  predicate: predicate, tables: [.dot, .symbol])
    }

    /// A built-in mark drawn as the warning triangle, in a color.
    ///
    /// - Parameters:
    ///   - number: Its number.
    ///   - name: What it's called.
    ///   - description: Its help. An empty one shows none.
    ///   - color: The triangle's color.
    ///   - predicate: The predicate an event matches.
    /// - Returns: The mark.
    static func warning(_ number: Int, _ name: String, _ description: String, color: Color = .yellow,
                        _ predicate: String) -> Indicator {
        mark(number, name, description, symbol: "exclamationmark.triangle.fill", color: color, predicate: predicate)
    }

    /// A default's twin. It's a built-in mark with the default's identity, name, predicate, symbol and color.
    ///
    /// - Parameters:
    ///   - number: The default's number.
    ///   - description: The mark's help.
    /// - Returns: The mark.
    static func twin(_ number: Int, _ description: String) -> Indicator {
        let indicator = shipped(number)
        return mark(number, indicator.name, description, symbol: indicator.symbol, color: indicator.color,
                    predicate: indicator.predicate)
    }
}
