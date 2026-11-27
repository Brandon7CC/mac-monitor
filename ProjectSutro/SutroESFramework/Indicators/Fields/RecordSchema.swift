//
//  RecordSchema.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - The schema's key paths
/// Every key path of the telemetry schema this build bundles (``TelemetrySchema``), with what its value is: the key
/// paths a rule can compare, and why the others can't be. Each array outside an array of objects has its size too,
/// as `event.exec.args.@count`, a number.
enum RecordSchema {
    /// The aggregate a key path ends with to read an array's size.
    static let count = "@count"

    /// What a key path is.
    enum Lookup: Equatable {
        /// A value a rule compares.
        case kind(IndicatorField.Kind)
        /// A key path of the record whose value a rule can't compare on its own, and why.
        case unsupported(String)
        /// Not a key path of the record.
        case absent
    }

    /// Every key path the schema has, read from the bundled schema once.
    static let paths: [String: Lookup] = {
        guard let data = try? TelemetrySchema.data(),
              let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return [:] }
        var reader = Reader(definitions: root["$defs"] as? [String: Any] ?? [:])
        reader.walk(root, path: [], inArray: false, through: [])
        return reader.paths
    }()

    /// - Parameter path: A key path, as in `event.exec.args`.
    /// - Returns: What it is.
    static func lookup(_ path: String) -> Lookup {
        guard let lookup = paths[path] else { return .absent }
        if Self.path(path, isUnder: evaluatedOnly) {
            return .unsupported("the Security Extension writes it once it has evaluated the event's indicators")
        }
        if case .kind = lookup, Self.path(path, isUnder: storedOnly) {
            return .unsupported("Mac Monitor writes it as it stores the event, "
                                + "after the Security Extension evaluates it")
        }
        return lookup
    }

    /// The key paths the record has and the Security Extension's event doesn't, or has otherwise: what Mac Monitor
    /// writes as it stores or exports an event (`RecordFieldParityTests`).
    static let storedOnly = ["seq_num", "global_seq_num", "telemetry_version", "event.gatekeeper_user_override.file",
                             "event.gatekeeper_user_override.sha256"]
    /// The indicators a record lists, which the Security Extension writes once it has evaluated the event, the
    /// undetermined ones too.
    static let evaluatedOnly = ["indicators"]

    /// - Parameters:
    ///   - path: A key path.
    ///   - prefixes: Key paths.
    /// - Returns: Is it one of them, under one, or one with `_` and more after it, as `indicators_undetermined` is?
    private static func path(_ path: String, isUnder prefixes: [String]) -> Bool {
        prefixes.contains { path == $0 || path.hasPrefix($0 + ".") || path.hasPrefix($0 + "_") }
    }

    /// Why a key path that ends with an aggregate, and that the record doesn't have, isn't one a rule compares: an
    /// aggregate other than `@count`, or the `@count` of what isn't an array of the record.
    ///
    /// - Parameter path: A key path ``lookup(_:)`` found absent, as in `event.close.yara_scan.@count`.
    /// - Returns: The problem, or `nil` for a key path that doesn't end with an aggregate.
    static func aggregateProblem(_ path: String) -> SensorProblem? {
        guard let dot = path.lastIndex(of: "."), path[path.index(after: dot)...].hasPrefix("@") else { return nil }
        let aggregate = path[path.index(after: dot)...]
        guard aggregate == count else {
            return .unsupported("\(aggregate) of \(path[..<dot]): it takes an array's .\(count) alone")
        }
        return .uncountable(path)
    }

    /// Walks the schema, from the root through each object's properties and each array's items.
    private struct Reader {
        /// The schema's definitions, by name.
        let definitions: [String: Any]
        /// The key paths found.
        var paths: [String: Lookup] = [:]

        /// - Parameters:
        ///   - node: A schema, or a part of one.
        ///   - path: Its key path's components.
        ///   - inArray: Is it inside an array of objects?
        ///   - through: The definitions on the way to it, so one that holds itself isn't walked forever.
        mutating func walk(_ node: [String: Any], path: [String], inArray: Bool, through: [String]) {
            var node = node, through = through
            if let reference = node["$ref"] as? String {
                let name = String(reference.split(separator: "/").last ?? "")
                guard !through.contains(name), let definition = definitions[name] as? [String: Any] else { return }
                node = definition
                through.append(name)
            }
            var scalars = Set<String>(), isObject = false
            /// The only combinator the schema may use: ``JSONSchemaCompiler`` refuses `oneOf` and `allOf`.
            for alternative in node["anyOf"] as? [[String: Any]] ?? [] {
                var resolved = alternative, inner = through
                if let reference = alternative["$ref"] as? String {
                    let name = String(reference.split(separator: "/").last ?? "")
                    guard !inner.contains(name), let definition = definitions[name] as? [String: Any] else { continue }
                    resolved = definition
                    inner.append(name)
                }
                if resolved["properties"] != nil || resolved["type"] as? String == "array" {
                    isObject = isObject || resolved["properties"] != nil
                    walk(resolved, path: path, inArray: inArray, through: inner)
                } else {
                    scalars.formUnion(Self.types(of: resolved))
                }
            }
            if let properties = node["properties"] as? [String: Any] {
                isObject = true
                for (key, value) in properties {
                    if let child = value as? [String: Any] {
                        walk(child, path: path + [key], inArray: inArray, through: through)
                    }
                }
            }
            let types = Self.types(of: node)
            if types.contains("array"), let items = node["items"] as? [String: Any] {
                let size = path + [RecordSchema.count]
                if Self.isString(items, definitions) {
                    note(path, inArray ? .unsupported("it's inside an array of objects") : .kind(.strings))
                } else {
                    walk(items, path: path, inArray: true, through: through)
                    let count = inArray ? "" : ", whose size is " + size.joined(separator: ".")
                    note(path, .unsupported("it's an array of other than strings" + count))
                }
                /// Its size, which a rule compares as a number, as `NSPredicate` reads it on the record.
                note(size, inArray ? .unsupported("it's inside an array of objects") : .kind(.number))
                return
            }
            scalars.formUnion(types.subtracting(["object"]))
            guard !path.isEmpty else { return }
            if isObject {
                note(path, .unsupported("it's an object"))
            } else if !scalars.isEmpty {
                note(path, inArray ? .unsupported("it's inside an array of objects") : Self.lookup(of: scalars))
            }
        }

        /// Keep what a key path is, unless a value it can be compared as is known already.
        ///
        /// - Parameters:
        ///   - path: The key path's components.
        ///   - lookup: What it is.
        private mutating func note(_ path: [String], _ lookup: Lookup) {
            let key = path.joined(separator: ".")
            if case .kind = paths[key] { return }
            paths[key] = lookup
        }

        /// - Parameter scalars: The JSON types a value can have.
        /// - Returns: What a rule compares it as.
        private static func lookup(of scalars: Set<String>) -> Lookup {
            switch scalars.subtracting(["null"]) {
            case ["string"]: .kind(.string)
            case ["integer"], ["number"], ["integer", "number"]: .kind(.number)
            case ["boolean"]: .kind(.boolean)
            case []: .unsupported("it's always null")
            default: .unsupported("its value can be of different kinds")
            }
        }

        /// - Parameter node: A schema.
        /// - Returns: The JSON types its `type`, `enum` or `const` names.
        private static func types(of node: [String: Any]) -> Set<String> {
            var types = Set<String>()
            if let type = node["type"] as? String { types.insert(type) }
            if let list = node["type"] as? [String] { types.formUnion(list) }
            for value in (node["enum"] as? [Any] ?? []) + [node["const"]].compactMap({ $0 }) {
                switch value {
                case is String: types.insert("string")
                case is NSNull: types.insert("null")
                case let number as NSNumber where CFGetTypeID(number) == CFBooleanGetTypeID(): types.insert("boolean")
                case is NSNumber: types.insert("number")
                default: break
                }
            }
            return types
        }

        /// - Parameters:
        ///   - node: An array's items.
        ///   - definitions: The schema's definitions.
        /// - Returns: Are they strings?
        private static func isString(_ node: [String: Any], _ definitions: [String: Any]) -> Bool {
            var node = node
            if let reference = node["$ref"] as? String,
               let definition = definitions[String(reference.split(separator: "/").last ?? "")] as? [String: Any] {
                node = definition
            }
            return types(of: node).subtracting(["null"]) == ["string"]
        }
    }
}
