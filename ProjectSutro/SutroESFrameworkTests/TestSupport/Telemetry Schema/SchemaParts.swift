//
//  SchemaParts.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - The schema's parts
/// A schema document's parts, found by walking its JSON as JSON Schema nests schemas: each definition, each
/// property's schema, `items`, and each `anyOf` alternative. A keyword's value that isn't a schema, such as an `enum`,
/// is never walked, and every property is, whatever its name: `type` included.
struct SchemaParts {
    /// An object's schema: one with `properties`.
    struct Object {
        /// Where it is.
        let location: String
        /// Does it allow no other keys (`additionalProperties: false`)?
        let closed: Bool
        /// Its keys, in order, with their schemas.
        let properties: [(key: String, schema: [String: Any])]
        /// The keys it requires.
        let required: Set<String>
    }
    
    /// Every object's schema.
    private(set) var objects: [Object] = []
    /// Every property's, `items`'s and definition's location.
    private(set) var locations: [String] = []
    /// Each location whose `type` lists several types, with them.
    private(set) var typeLists: [(location: String, types: [JSONType])] = []
    /// Each `anyOf`'s location, with its number of alternatives.
    private(set) var branches: [(location: String, count: Int)] = []
    
    /// Each object's keys that aren't required, by the object's location.
    var optionalKeys: [(object: String, key: String)] {
        objects.flatMap { object in
            object.properties.map(\.key).filter { !object.required.contains($0) }.map { (object.location, $0) }
        }
    }
    
    /// - Parameter document: The schema, as `JSONSerialization` would read it.
    init(_ document: Any) {
        guard let root = document as? [String: Any] else { return }
        walk(root, at: "#")
        for (name, definition) in (root["$defs"] as? [String: Any] ?? [:]).sorted(by: { $0.key < $1.key }) {
            let location = JSONSchemaCompiler.definitionsPrefix + JSONSchemaCompiler.escape(name)
            locations.append(location)
            walk(definition as? [String: Any] ?? [:], at: location)
        }
    }
    
    /// Collect a schema's parts and its subschemas'.
    ///
    /// - Parameters:
    ///   - schema: The schema.
    ///   - location: Its location.
    private mutating func walk(_ schema: [String: Any], at location: String) {
        if let types = schema["type"] as? [String], types.count > 1 {
            typeLists.append((location, types.compactMap(JSONType.init(rawValue:))))
        }
        if let list = schema["properties"] as? [String: Any] {
            let properties = list.sorted { $0.key < $1.key }.map { key, value in
                (key: key, schema: value as? [String: Any] ?? [:])
            }
            objects.append(Object(location: location, closed: schema["additionalProperties"] as? Bool == false,
                                  properties: properties, required: Set(schema["required"] as? [String] ?? [])))
            for (key, property) in properties {
                let place = "\(location)/properties/\(JSONSchemaCompiler.escape(key))"
                locations.append(place)
                walk(property, at: place)
            }
        }
        if let items = schema["items"] as? [String: Any] {
            locations.append("\(location)/items")
            walk(items, at: "\(location)/items")
        }
        if let alternatives = schema["anyOf"] as? [[String: Any]] {
            branches.append((location, alternatives.count))
            for (index, alternative) in alternatives.enumerated() {
                walk(alternative, at: "\(location)/anyOf/\(index)")
            }
        }
    }
}
