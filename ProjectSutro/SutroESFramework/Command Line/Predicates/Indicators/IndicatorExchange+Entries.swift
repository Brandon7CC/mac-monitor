//
//  IndicatorExchange+Entries.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - A file's entries as written
public extension IndicatorExchange {
    /// A file's indicators as JSON objects, each with only the keys it has, for `macmonitor indicators edit --file`:
    /// decoding one as an ``Indicator`` would make up what it leaves out, a new identity included. It reads the shapes
    /// ``indicators(from:)`` reads, the file, a bare array or one indicator alone, with the same checks of the format
    /// and version.
    ///
    /// - Parameter data: A file of indicators.
    /// - Returns: Each indicator's object, in the file's order.
    /// - Throws: ``ImportError`` when it isn't JSON, is another format or a newer version, has an entry that isn't an
    ///   object, or has none.
    static func entryObjects(from data: Data) throws -> [[String: Any]] {
        let object = try checkedJSON(data)
        let listed: [Any]
        if isFile(object) {
            guard let indicators = (object as? [String: Any])?["indicators"] as? [Any] else {
                throw ImportError(message: "The file's indicators can't be read.")
            }
            listed = indicators
        } else {
            listed = object as? [Any] ?? [object]
        }
        let entries = listed.compactMap { $0 as? [String: Any] }
        guard entries.count == listed.count else {
            throw ImportError(message: "An indicator in the file isn't a JSON object.")
        }
        guard !entries.isEmpty else { throw ImportError(message: "The file has no indicators.") }
        return entries
    }
}
