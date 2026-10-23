//
//  SchemaKeyPaths.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - The schema at eslogger's paths
/// The schema's keys at the paths `Fixtures/eslogger-keys.json` uses: the envelope's, each event's (relative to the
/// event's object), and the process's, file's, stat's and audit token's, which stay references elsewhere.
struct SchemaKeyPaths {
    /// One key.
    struct Key {
        /// Its effective origin: its own mark, or Mac Monitor's under a Mac Monitor key.
        let origin: KeyOrigin
        /// Its value's schema.
        let schema: [String: Any]
        /// Is it required?
        let required: Bool
        /// When the schema says it's absent.
        let absence: Absence?
    }
    
    /// The definitions eslogger's keys name as types rather than spell out.
    static let named: Set<String> = ["process", "file", "stat", "audit_token"]
    /// What every reference to a definition starts with.
    private static let prefix = JSONSchemaCompiler.definitionsPrefix
    
    /// Each scope's keys, by path.
    private(set) var scopes: [String: [String: Key]] = [:]
    /// The schema's definitions.
    private let definitions: [String: [String: Any]]
    /// Each property's key in the source, by location.
    private let keys: [String: SchemaGenerator.KeyPlace]
    
    /// - Parameters:
    ///   - document: The schema, as `JSONSerialization` would read it.
    ///   - keys: Each property's key in the source, by location.
    init(_ document: Any, keys: [String: SchemaGenerator.KeyPlace]) {
        let root = document as? [String: Any] ?? [:]
        definitions = (root["$defs"] as? [String: Any] ?? [:]).compactMapValues { $0 as? [String: Any] }
        self.keys = keys
        collect(root, at: "#", path: "", scope: "envelope", inherited: nil)
        for event in TelemetrySchemaSource.events {
            /// An event without keys (`cs_invalidated`) is a scope too.
            scopes["events.\(event.name)"] = [:]
            collect(definitions[event.definition] ?? [:], at: Self.prefix + event.definition, path: "",
                    scope: "events.\(event.name)", inherited: nil)
        }
        for name in Self.named {
            collect(definitions[name] ?? [:], at: Self.prefix + name, path: "", scope: "definitions.\(name)",
                    inherited: nil)
        }
    }
    
    /// Collect a schema's keys, reading through references (but to the named definitions and the events) and
    /// alternatives.
    ///
    /// - Parameters:
    ///   - schema: The schema.
    ///   - location: Its location.
    ///   - path: Its path in the scope, empty for the scope's object.
    ///   - scope: The scope.
    ///   - inherited: Mac Monitor's origin, under a Mac Monitor key.
    private mutating func collect(_ schema: [String: Any], at location: String, path: String, scope: String,
                                  inherited: KeyOrigin?) {
        if let reference = (schema["$ref"] as? String)?.replacingOccurrences(of: Self.prefix, with: ""),
           !Self.named.contains(reference), reference != "event" {
            collect(definitions[reference] ?? [:], at: Self.prefix + reference, path: path, scope: scope,
                    inherited: inherited)
        }
        for (index, branch) in (schema["anyOf"] as? [[String: Any]] ?? []).enumerated() {
            collect(branch, at: "\(location)/anyOf/\(index)", path: path, scope: scope, inherited: inherited)
        }
        if let items = schema["items"] as? [String: Any] {
            /// eslogger's keys list an array's elements when they're objects.
            if kinds(of: items) == ["object"] {
                scopes[scope, default: [:]]["\(path)[]"] = Key(origin: inherited ?? .eslogger, schema: items,
                                                             required: true, absence: nil)
            }
            collect(items, at: "\(location)/items", path: "\(path)[]", scope: scope, inherited: inherited)
        }
        let required = Set(schema["required"] as? [String] ?? [])
        for (name, value) in schema["properties"] as? [String: Any] ?? [:] {
            let property = value as? [String: Any] ?? [:]
            let place = "\(location)/properties/\(JSONSchemaCompiler.escape(name))"
            let mark = KeyOrigin(rawValue: property["x-mac-monitor-origin"] as? String ?? "")
            let origin = inherited ?? mark ?? .eslogger
            let child = path.isEmpty ? name : "\(path).\(name)"
            scopes[scope, default: [:]][child] = Key(origin: origin, schema: property,
                                                     required: required.contains(name),
                                                     absence: keys[place]?.key.absence)
            collect(property, at: place, path: child, scope: scope, inherited: origin == .macMonitor ? origin : nil)
        }
    }
    
    /// A value's types as the fixture names them: `int`, `string(time)`, `array[string]`, `process`, `null`.
    ///
    /// - Parameter schema: The value's schema.
    /// - Returns: Its types.
    func kinds(of schema: [String: Any]) -> Set<String> {
        if let reference = (schema["$ref"] as? String)?.replacingOccurrences(of: Self.prefix, with: "") {
            return Self.named.contains(reference) ? [reference] : kinds(of: definitions[reference] ?? [:])
        }
        if let branches = schema["anyOf"] as? [[String: Any]] { return branches.reduce([]) { $0.union(kinds(of: $1)) } }
        let types = (schema["type"] as? String).map { [$0] } ?? schema["type"] as? [String] ?? []
        return Set(types.map { type -> String in
            switch type {
            case "integer": return "int"
            case "boolean": return "bool"
            case "string":
                switch schema["pattern"] as? String {
                case SchemaPattern.timespec.rawValue?, SchemaPattern.timeval.rawValue?: return "string(time)"
                case SchemaPattern.cdhash.rawValue?, SchemaPattern.sha256.rawValue?: return "string(hex)"
                default: return "string"
                }
            case "array":
                let element = kinds(of: schema["items"] as? [String: Any] ?? [:])
                return element == ["string"] || element == ["int"] ? "array[\(element.first!)]" : "array"
            default: return type
            }
        })
    }
}
