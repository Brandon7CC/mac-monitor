//
//  StreamFilter+Records.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation


// MARK: - Events
public extension StreamFilter.Predicate {
    /// Evaluate the predicate on an event's record, the JSON Export telemetry writes for it.
    ///
    /// Call on the event's context's queue. Prefetch ``ESMessage/recordPrefetchKeyPaths(in:)`` for many events.
    ///
    /// - Parameter message: The event.
    /// - Returns: Does its record match?
    /// - Throws: ``StreamFilterError`` if the predicate can't be evaluated on it, or the encoder's error.
    func evaluate(on message: ESMessage) throws -> Bool {
        try evaluate(on: Self.record(of: message))
    }

    /// Keep an event the predicate's `SUBQUERY`s pick as a related event (``collect(_:)``).
    ///
    /// Call on the event's context's queue, for every event before evaluating the predicate on any.
    ///
    /// - Parameter message: The event.
    /// - Throws: ``StreamFilterError`` if a `SUBQUERY`'s conditions can't be evaluated on it, or the encoder's error.
    func collect(_ message: ESMessage) throws {
        try collect(Self.record(of: message))
    }

    /// - Parameter message: An event.
    /// - Returns: Its record, the JSON Export telemetry writes for it.
    /// - Throws: The encoder's error.
    private static func record(of message: ESMessage) throws -> NSDictionary {
        try JSONSerialization.jsonObject(with: JSONEncoder().encode(message)) as? NSDictionary ?? NSDictionary()
    }
}


// MARK: - Records for predicates
/// A record as a predicate sees it. A key path only looks keys up in the record's objects, at any depth: an array's
/// key is each of its objects' key, or its `@count`, `@sum`, `@avg`, `@min` or `@max`, and a value's is `nil`. Plain
/// key-value coding would call any method a key names on a value (`path.release`). Not thread-safe.
final class PredicateRecord: NSObject {
    /// The aggregates an array takes.
    static let aggregates: Set<String> = ["@count", "@sum", "@avg", "@min", "@max"]
    /// The JSON object.
    let values: NSDictionary

    /// - Parameter values: A JSON object.
    init(_ values: NSDictionary) {
        self.values = values
    }

    /// A JSON value as a predicate sees it: objects as records, and arrays with their objects as records.
    ///
    /// - Parameter value: The value.
    /// - Returns: What a predicate compares.
    static func wrap(_ value: Any?) -> Any? {
        switch value {
        case let object as NSDictionary: return PredicateRecord(object)
        case let array as NSArray: return array.map { wrap($0) ?? NSNull() } as NSArray
        default: return value
        }
    }

    /// One key of a value: a record's key, an array's aggregate or each of its records' key, and `nil` for anything
    /// else.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - key: The key.
    /// - Returns: The key's value.
    static func value(of value: Any?, forKey key: String) -> Any? {
        switch value {
        case let record as PredicateRecord:
            return record.value(forKey: key)
        case let array as NSArray where aggregates.contains(key):
            guard key != "@count" else { return array.count }
            /// On numbers only, whose `self` is all key-value coding calls.
            return (array.filter { $0 is NSNumber } as NSArray).value(forKeyPath: key + ".self")
        case let array as NSArray:
            return array.map { (($0 as? PredicateRecord)?.value(forKey: key)) ?? NSNull() } as NSArray
        default:
            return nil
        }
    }

    /// A key's value, never a method's.
    ///
    /// - Parameter key: The key.
    /// - Returns: The value, or the object's `@count`.
    override func value(forKey key: String) -> Any? {
        key == "@count" ? values.count : Self.wrap(values[key])
    }

    /// A key path's value, a key at a time.
    ///
    /// - Parameter keyPath: The key path.
    /// - Returns: The value, or `nil` past a value.
    override func value(forKeyPath keyPath: String) -> Any? {
        keyPath.split(separator: ".", omittingEmptySubsequences: false)
            .reduce(self as Any?) { value, key in Self.value(of: value, forKey: String(key)) }
    }

    /// No key is undefined: one the record lacks is `nil`.
    ///
    /// - Parameter key: The key.
    /// - Returns: `nil`.
    override func value(forUndefinedKey key: String) -> Any? {
        nil
    }
}
