//
//  RecordFields.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/9/26.
//

import Foundation


// MARK: - Record fields
/// The record fields this process has given numbers (``IndicatorField``): each key path a rule named that isn't a
/// direct field, with its kind, numbered after the direct fields in the order rules first named them. A number is never
/// taken back, so a compiled program's fields keep naming the same paths. The telemetry schema bounds how many there
/// can be.
///
/// **Threading:** thread-safe. Only compiling a rule and describing a field take its lock. Reading an event's values
/// never does.
final class RecordFields: @unchecked Sendable {
    /// The one table, for every set in the process.
    static let shared = RecordFields()

    /// Guards the table.
    private let lock = NSLock()
    /// Each record field's key path and kind, by its number less the direct fields'.
    private var descriptors: [(path: String, kind: IndicatorField.Kind)] = []
    /// Each record field by its key path.
    private var byPath: [String: IndicatorField] = [:]

    /// - Parameters:
    ///   - path: A key path of the record that isn't a direct field's.
    ///   - kind: What its value is.
    /// - Returns: Its field, numbered the first time it's asked for.
    func field(_ path: String, kind: IndicatorField.Kind) -> IndicatorField {
        lock.withLock {
            if let field = byPath[path] { return field }
            let field = IndicatorField(rawValue: UInt16(IndicatorField.allCases.count + descriptors.count))
            descriptors.append((path, kind))
            byPath[path] = field
            return field
        }
    }

    /// - Parameter field: A record field.
    /// - Returns: Its key path and kind.
    func descriptor(of field: IndicatorField) -> (path: String, kind: IndicatorField.Kind) {
        lock.withLock { descriptors[Int(field.rawValue) - IndicatorField.allCases.count] }
    }
}
