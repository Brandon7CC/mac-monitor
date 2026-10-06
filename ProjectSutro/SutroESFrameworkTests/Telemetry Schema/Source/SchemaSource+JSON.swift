//
//  SchemaSource+JSON.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Generating the schema
/// Turns the description of the export into the schema's JSON, remembering which key each property location
/// describes, for the tests that check the schema against the exports.
final class SchemaGenerator {
    /// A key, and the location of the object that has it.
    struct KeyPlace {
        /// The key.
        let key: SchemaKey
        /// The location of its object's schema.
        let object: String
    }
    
    /// The order the schema writes a schema object's keywords in: identity first, `$defs` last.
    static let keywordOrder = ["$schema", "$id", "title", "description", "x-mac-monitor-origin", "$ref", "type",
                               "const", "enum", "pattern", "minProperties", "maxProperties", "properties", "required",
                               "additionalProperties", "items", "anyOf", "$defs"]
    
    /// Each property's location, with its key.
    private(set) var keys: [String: KeyPlace] = [:]
    
    /// The whole schema.
    ///
    /// - Parameters:
    ///   - root: The record's object.
    ///   - definitions: The shared definitions, by name.
    ///   - identity: `$schema`, `$id`, `title` and `description`, in that order.
    /// - Returns: The schema document.
    func document(root: SchemaObject, definitions: [String: SchemaObject],
                  identity: [(String, String)]) -> OrderedJSON {
        var members = Dictionary(uniqueKeysWithValues: identity.map { ($0.0, OrderedJSON.string($0.1)) })
        members.merge(object(root, at: "#")) { first, _ in first }
        members["$defs"] = .object(definitions.keys.sorted().map { name in
            OrderedJSON.Member(key: name, value: schema(.object(definitions[name]!), at: "#/$defs/\(name)"))
        })
        return ordered(members)
    }
    
    /// A value's schema.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - location: The schema's location.
    ///   - annotations: Keywords to add, such as the key's origin and description.
    /// - Returns: The schema object.
    func schema(_ value: SchemaValue, at location: String, annotations: [String: OrderedJSON] = [:]) -> OrderedJSON {
        ordered(keywords(value, at: location).merging(annotations) { first, _ in first })
    }
    
    /// A value's keywords.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - location: The schema's location.
    /// - Returns: The keywords, unordered.
    private func keywords(_ value: SchemaValue, at location: String) -> [String: OrderedJSON] {
        switch value {
        case .string: return ["type": .string("string")]
        case .integer: return ["type": .string("integer")]
        case .boolean: return ["type": .string("boolean")]
        case .null: return ["type": .string("null")]
        case .pattern(let pattern): return ["type": .string("string"), "pattern": .string(pattern.rawValue)]
        case .constant(let text): return ["type": .string("string"), "const": .string(text)]
        case .values(let list): return ["type": .string("string"), "enum": .array(list.map(OrderedJSON.string))]
        case .integers(let list): return ["type": .string("integer"), "enum": .array(list.map(OrderedJSON.integer))]
        case .array(let element): return ["type": .string("array"), "items": schema(element, at: "\(location)/items")]
        case .object(let object): return self.object(object, at: location)
        case .ref(let name): return ["$ref": .string("#/$defs/\(name)")]
        case .nullable(let inner):
            var simple = keywords(inner, at: location)
            if case .string(let type)? = simple["type"], simple["enum"] == nil, simple["const"] == nil,
               ["string", "integer", "boolean"].contains(type) {
                simple["type"] = .array([.string(type), .string("null")])
                return simple
            }
            return ["anyOf": .array([schema(.null, at: "\(location)/anyOf/0"),
                                     schema(inner, at: "\(location)/anyOf/1")])]
        case .either(let list):
            return ["anyOf": .array(list.enumerated().map { schema($1, at: "\(location)/anyOf/\($0)") })]
        }
    }
    
    /// An object's keywords: its keys, which are required, and that it has no others.
    ///
    /// - Parameters:
    ///   - object: The object.
    ///   - location: Its schema's location.
    /// - Returns: The keywords, unordered.
    private func object(_ object: SchemaObject, at location: String) -> [String: OrderedJSON] {
        var members: [String: OrderedJSON] = ["type": .string("object"), "additionalProperties": .boolean(false)]
        if let description = object.description { members["description"] = .string(description) }
        members["properties"] = .object(object.keys.sorted { $0.name < $1.name }.map { key in
            let place = "\(location)/properties/\(JSONSchemaCompiler.escape(key.name))"
            keys[place] = KeyPlace(key: key, object: location)
            var annotations: [String: OrderedJSON] = ["x-mac-monitor-origin": .string(key.origin.rawValue)]
            if let description = key.fullDescription { annotations["description"] = .string(description) }
            return OrderedJSON.Member(key: key.name, value: schema(key.value, at: place, annotations: annotations))
        })
        let required = object.keys.filter { $0.absence == nil }.map(\.name).sorted()
        if !required.isEmpty { members["required"] = .array(required.map(OrderedJSON.string)) }
        if let count = object.keyCount {
            members["minProperties"] = .integer(count.lowerBound)
            members["maxProperties"] = .integer(count.upperBound)
        }
        return members
    }
    
    /// A schema object with its keywords in ``keywordOrder``.
    ///
    /// - Parameter members: The keywords.
    /// - Returns: The object.
    private func ordered(_ members: [String: OrderedJSON]) -> OrderedJSON {
        let unknown = Set(members.keys).subtracting(Self.keywordOrder)
        precondition(unknown.isEmpty, "Keywords without a place in the order: \(unknown)")
        return .object(Self.keywordOrder.compactMap { key in
            members[key].map { OrderedJSON.Member(key: key, value: $0) }
        })
    }
}
