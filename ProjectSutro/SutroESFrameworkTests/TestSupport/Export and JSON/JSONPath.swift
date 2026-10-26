//
//  JSONPath.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation


// MARK: - A step into JSON
/// A step into a JSON value: a key of an object, or an index of an array.
enum JSONStep: ExpressibleByStringLiteral, ExpressibleByIntegerLiteral {
    case key(String), index(Int)

    /// A key, written as a string literal.
    ///
    /// - Parameter key: The key.
    init(stringLiteral key: String) { self = .key(key) }

    /// An index, written as an integer literal.
    ///
    /// - Parameter index: The index.
    init(integerLiteral index: Int) { self = .index(index) }
}


// MARK: - The value at a path
extension Dictionary where Key == String, Value == Any {
    /// The value at a path through objects and arrays, written out: `record[path: "event", "exec", "args", 0]`.
    ///
    /// - Parameter path: The steps.
    subscript(path path: JSONStep...) -> Any? {
        get { self[path: path] }
        set { self[path: path] = newValue }
    }

    /// The value at a path through objects and arrays, or `nil` if a step isn't there. Setting it goes through the
    /// keys and indexes the object has, makes the objects it lacks, and removes the last key for `nil`.
    ///
    /// - Parameter path: The steps.
    subscript(path path: [JSONStep]) -> Any? {
        get {
            path.reduce(self as Any?) { found, step in
                switch step {
                case .key(let key):
                    return (found as? [String: Any])?[key]
                case .index(let index):
                    return (found as? [Any]).flatMap { $0.indices.contains(index) ? $0[index] : nil }
                }
            }
        }
        set {
            /// The JSON value `current` with the value at `path` replaced.
            func replacing(in current: Any?, at path: ArraySlice<JSONStep>) -> Any? {
                guard let step = path.first else { return newValue }
                switch step {
                case .key(let key):
                    var object = current as? [String: Any] ?? [:]
                    object[key] = replacing(in: object[key], at: path.dropFirst())
                    return object
                case .index(let index):
                    var array = current as? [Any] ?? []
                    array[index] = replacing(in: array[index], at: path.dropFirst()) ?? NSNull()
                    return array
                }
            }
            self = replacing(in: self, at: path[...]) as? [String: Any] ?? [:]
        }
    }
}
