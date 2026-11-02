//
//  RecordKeyPaths.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/23/26.
//

import Foundation


// MARK: - Key paths
/// Every key path a record has, from the bundled telemetry schema, with its type: what a predicate's key paths are
/// checked against, what the predicate editor completes and lists. An array's objects' keys follow the array's path,
/// as `ANY event.exec.fds.fd` reads them.
public final class RecordKeyPaths {
    /// One key path.
    public struct Node {
        /// Its JSON type: string, integer, number, boolean, array, object or null.
        public let type: String
        /// Its keys, by name, sorted.
        public fileprivate(set) var children: [String] = []
        /// The values it takes, when the schema lists them, such as `es_event_type`'s.
        public fileprivate(set) var values: [String] = []
        /// What it is, as the schema describes it, if it does.
        public fileprivate(set) var summary: String?
        /// Is it inside an array, an array's objects' key?
        public let isInArray: Bool
    }

    /// The bundled schema's key paths. Empty if it can't be read.
    public static let shared = RecordKeyPaths()

    /// Every key path, `""` for the record itself.
    public private(set) var nodes: [String: Node] = [:]

    /// Every key path, in order, without the record itself.
    public private(set) lazy var paths: [String] = nodes.keys.filter { !$0.isEmpty }.sorted()

    /// - Parameter schema: The schema's JSON, the bundled one by default.
    init(schema: Data? = try? TelemetrySchema.data()) {
        guard let data = schema, let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return
        }
        let definitions = root["$defs"] as? [String: Any] ?? [:]
        walk(root, path: "", definitions: definitions, references: [], inArray: false)
        for path in nodes.keys where !path.isEmpty {
            let parent = path.split(separator: ".").dropLast().joined(separator: ".")
            nodes[parent]?.children.append(String(path.split(separator: ".").last ?? ""))
        }
        for path in nodes.keys { nodes[path]?.children.sort() }
    }

    /// Add a schema node's key path, and its keys'.
    ///
    /// - Parameters:
    ///   - node: The schema node.
    ///   - path: Its key path.
    ///   - definitions: The schema's `$defs`.
    ///   - references: The `$ref`s followed to get here, which aren't followed again.
    ///   - inArray: Is it inside an array?
    private func walk(_ node: [String: Any], path: String, definitions: [String: Any], references: Set<String>,
                      inArray: Bool) {
        var references = references
        let alternatives = resolve(node, definitions, &references)
        let types = alternatives.flatMap { ($0["type"] as? [String]) ?? [($0["type"] as? String) ?? "object"] }
        let type = types.first { $0 != "null" } ?? "null"
        var entry = Node(type: type, isInArray: inArray)
        entry.values = alternatives.flatMap { ($0["enum"] as? [Any] ?? []).compactMap { $0 as? String } }
        /// The key's own description, else its type's.
        entry.summary = node["description"] as? String
            ?? alternatives.lazy.compactMap { $0["description"] as? String }.first
        nodes[path] = entry
        for alternative in alternatives {
            if let properties = alternative["properties"] as? [String: Any] {
                for (name, child) in properties {
                    guard let child = child as? [String: Any] else { continue }
                    walk(child, path: path.isEmpty ? name : path + "." + name, definitions: definitions,
                         references: references, inArray: inArray)
                }
            }
            if let items = alternative["items"] as? [String: Any] {
                var itemReferences = references
                for item in resolve(items, definitions, &itemReferences) {
                    for (name, child) in item["properties"] as? [String: Any] ?? [:] {
                        guard let child = child as? [String: Any] else { continue }
                        walk(child, path: path + "." + name, definitions: definitions, references: itemReferences,
                             inArray: true)
                    }
                }
            }
        }
    }

    /// A schema node's alternatives, with `$ref` and `anyOf` followed: the null one left out.
    ///
    /// - Parameters:
    ///   - node: The schema node.
    ///   - definitions: The schema's `$defs`.
    ///   - references: The `$ref`s followed so far, which a cycle stops at.
    /// - Returns: The alternatives, each with its own `type`, `properties` or `items`.
    private func resolve(_ node: [String: Any], _ definitions: [String: Any],
                         _ references: inout Set<String>) -> [[String: Any]] {
        if let reference = node["$ref"] as? String {
            let name = String(reference.split(separator: "/").last ?? "")
            guard references.insert(name).inserted, let target = definitions[name] as? [String: Any] else { return [] }
            return resolve(target, definitions, &references)
        }
        if let options = node["anyOf"] as? [[String: Any]] {
            return options.filter { ($0["type"] as? String) != "null" }
                .flatMap { resolve($0, definitions, &references) }
        }
        return [node]
    }

    // MARK: Checking
    /// How many of a key path's keys lead somewhere, from the record. An aggregate (`@count`) follows any key.
    ///
    /// - Parameter keys: The key path's keys.
    /// - Returns: The number of leading keys that are where the path puts them: `keys.count` for a key path a record
    ///   has.
    public func validCount(of keys: [String]) -> Int {
        var path = ""
        for (index, key) in keys.enumerated() {
            if key.hasPrefix("@") { continue }
            let next = path.isEmpty ? key : path + "." + key
            guard nodes[next] != nil else { return index }
            path = next
        }
        return keys.count
    }

    /// The key path meant by one a record doesn't have: the shortest that ends with all of its keys, such as
    /// `event.create.destination` for `create.destination`, else the one with its first misplaced key that shares
    /// the most keys with it.
    ///
    /// - Parameter keys: A key path's keys, which a record doesn't have.
    /// - Returns: The key path meant, or `nil` if none is close.
    public func suggestion(for keys: [String]) -> String? {
        let named = keys.filter { !$0.hasPrefix("@") }
        let tail = "." + named.joined(separator: ".")
        if let ending = paths.filter({ $0.hasSuffix(tail) }).min(by: { $0.count < $1.count }) { return ending }
        let index = validCount(of: named)
        guard index < named.count else { return nil }
        let key = named[index]
        /// How many leading keys a key path shares with this one, then the shorter.
        func closeness(_ path: String) -> (Int, Int) {
            (zip(path.split(separator: "."), named).prefix { String($0) == $1 }.count, -path.count)
        }
        return paths.filter { $0 == key || $0.hasSuffix("." + key) }.max { closeness($0) < closeness($1) }
    }
}
