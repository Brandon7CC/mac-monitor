//
//  JSONSchemaCompiler.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Compiler
/// Compiles a schema's objects into ``JSONSchemaNode``s, rejecting every keyword outside the supported subset so a
/// constraint is never silently ignored.
///
/// Supported: `type`, `enum`, `const`, `pattern`, `properties`, `required`, `additionalProperties` (a Boolean),
/// `minProperties`, `maxProperties`, `items` (one schema), `anyOf`, and `$ref` to the root's `$defs`; the
/// annotations `$comment`, `title`, `description`, `examples`, `default`, `deprecated` and `format` (not checked), any
/// `x-` keyword, and `$schema` (draft 2020-12), `$id` and `$defs` at the root. A subschema may also be `true`.
///
/// Compilation takes two passes: every object is compiled, then each `$ref` is looked up by name and the references are
/// checked for loops.
final class JSONSchemaCompiler {
    /// A node's keywords, gathered before the node is made.
    struct Keywords {
        var types: [JSONType]?
        var constant: JSONScalar?
        var values: Set<JSONScalar>?
        var pattern: JSONPattern?
        var properties: [String: JSONSchemaNode] = [:]
        var required: Set<String> = []
        var closed = false
        var minProperties: Int?, maxProperties: Int?
        var items: JSONSchemaNode?
        var anyOf: [JSONSchemaNode] = []
        var reference: String?
        var origin: KeyOrigin?
    }
    
    /// The meta-schema a schema may name in `$schema`.
    static let draft = "https://json-schema.org/draft/2020-12/schema"
    /// Keywords that only annotate, and aren't checked.
    static let annotations: Set<String> = ["$comment", "title", "description", "examples", "default", "deprecated",
                                           "format"]
    /// What every supported `$ref` starts with.
    static let definitionsPrefix = "#/$defs/"
    
    /// The root's `$defs`, by name.
    private(set) var definitions: [String: JSONSchemaNode] = [:]
    /// Every node compiled, for the second pass.
    private var nodes: [JSONSchemaNode] = []
    /// Each node's `$ref` as the schema spells it, for errors.
    private var spelledReferences: [ObjectIdentifier: String] = [:]
    
    /// Compile a schema object and everything in it, keywords and keys in order, so a schema with several problems
    /// always reports the same one.
    ///
    /// - Parameters:
    ///   - value: The schema: a JSON object, or `true`.
    ///   - location: Its JSON pointer.
    ///   - isRoot: Is it the root, where `$schema`, `$id` and `$defs` may appear?
    /// - Returns: The node.
    /// - Throws: A ``TelemetrySchemaError`` for a keyword outside the subset or with an invalid value.
    func compile(_ value: Any, at location: String, isRoot: Bool = false) throws -> JSONSchemaNode {
        if JSONType(of: value) == .boolean {
            guard (value as! NSNumber).boolValue else {
                throw TelemetrySchemaError.unsupportedKeyword("false", at: location)
            }
            return remember(JSONSchemaNode(location: location, keywords: Keywords()), spelling: nil)
        }
        guard let object = value as? [String: Any] else {
            throw TelemetrySchemaError.invalidKeyword("schema", at: location)
        }
        var keywords = Keywords(), spelling: String?
        for key in object.keys.sorted() {
            let value = object[key]!
            /// The keyword's error, for a value it can't have.
            func invalid() -> TelemetrySchemaError { .invalidKeyword(key, at: location) }
            /// A value read from the keyword's, or the keyword's error if there's none.
            func valid<T>(_ read: T?) throws -> T {
                guard let read else { throw invalid() }
                return read
            }
            switch key {
            case "type": keywords.types = try valid(Self.types(value))
            case "const": keywords.constant = try valid(JSONScalar(value))
            case "enum":
                guard let list = value as? [Any], !list.isEmpty else { throw invalid() }
                keywords.values = Set(try list.map { try valid(JSONScalar($0)) })
            case "pattern":
                guard let pattern = (value as? String).flatMap(JSONPattern.init) else { throw invalid() }
                keywords.pattern = pattern
            case "properties":
                guard let list = value as? [String: Any] else { throw invalid() }
                for (name, schema) in list.sorted(by: { $0.key < $1.key }) {
                    keywords.properties[name] = try compile(schema, at: "\(location)/properties/\(Self.escape(name))")
                }
            case "required":
                guard let list = value as? [String], Set(list).count == list.count else { throw invalid() }
                keywords.required = Set(list)
            case "additionalProperties":
                guard JSONType(of: value) == .boolean else {
                    throw TelemetrySchemaError.unsupportedKeyword(key, at: location)
                }
                keywords.closed = !(value as! NSNumber).boolValue
            case "minProperties", "maxProperties":
                guard case .integer(let count)? = JSONScalar(value), count >= 0 else { throw invalid() }
                if key == "minProperties" { keywords.minProperties = count } else { keywords.maxProperties = count }
            case "items":
                guard !(value is [Any]) else { throw invalid() }
                keywords.items = try compile(value, at: "\(location)/items")
            case "anyOf":
                guard let list = value as? [Any], !list.isEmpty else { throw invalid() }
                keywords.anyOf = try list.enumerated().map { try compile($1, at: "\(location)/anyOf/\($0)") }
            case "$ref":
                guard let text = value as? String, let name = Self.definitionName(text) else { throw invalid() }
                (keywords.reference, spelling) = (name, text)
            case "x-mac-monitor-origin":
                keywords.origin = try valid((value as? String).flatMap(KeyOrigin.init(rawValue:)))
            case "$defs" where isRoot:
                guard let list = value as? [String: Any] else { throw invalid() }
                for (name, schema) in list.sorted(by: { $0.key < $1.key }) {
                    definitions[name] = try compile(schema, at: Self.definitionsPrefix + Self.escape(name))
                }
            case "$schema" where isRoot:
                guard let text = value as? String, [Self.draft, Self.draft + "#"].contains(text) else {
                    throw invalid()
                }
            case "$id" where isRoot:
                guard value is String else { throw invalid() }
            case _ where Self.annotations.contains(key) || key.hasPrefix("x-"):
                continue
            default:
                throw TelemetrySchemaError.unsupportedKeyword(key, at: location)
            }
        }
        return remember(JSONSchemaNode(location: location, keywords: keywords), spelling: spelling)
    }
    
    /// Check that every `$ref` names a definition, and that no chain of `$ref`s and `anyOf`s comes back to where it
    /// started without reading into the value: checking it would never end. Recursion through `properties` or
    /// `items` is fine, since each step reads a smaller value.
    ///
    /// - Throws: ``TelemetrySchemaError/unresolvedReference(_:at:)`` or ``TelemetrySchemaError/referenceCycle(at:)``.
    func resolveReferences() throws {
        for node in nodes {
            if let name = node.reference, definitions[name] == nil {
                let spelling = spelledReferences[ObjectIdentifier(node)] ?? name
                throw TelemetrySchemaError.unresolvedReference(spelling, at: node.location)
            }
        }
        /// `false` while a node's successors are being visited, `true` once they all have been.
        var visited: [ObjectIdentifier: Bool] = [:]
        /// Visit a node's alternatives and the definition it refers to, depth first, failing at a node visited again
        /// before its successors are done.
        func visit(_ node: JSONSchemaNode) throws {
            switch visited[ObjectIdentifier(node)] {
            case true?: return
            case false?: throw TelemetrySchemaError.referenceCycle(at: node.location)
            case nil: break
            }
            visited[ObjectIdentifier(node)] = false
            for next in node.anyOf + [node.reference.flatMap { definitions[$0] }].compactMap({ $0 }) { try visit(next) }
            visited[ObjectIdentifier(node)] = true
        }
        try nodes.forEach(visit)
    }
    
    /// Keep a node for the second pass.
    ///
    /// - Parameters:
    ///   - node: The node.
    ///   - spelling: Its `$ref` as the schema spells it.
    /// - Returns: The node.
    private func remember(_ node: JSONSchemaNode, spelling: String?) -> JSONSchemaNode {
        nodes.append(node)
        if let spelling { spelledReferences[ObjectIdentifier(node)] = spelling }
        return node
    }
    
    /// A `type` keyword's types.
    ///
    /// - Parameter value: A type name, or a non-empty array of different ones.
    /// - Returns: The types, or `nil` if the value isn't one of those.
    private static func types(_ value: Any) -> [JSONType]? {
        let names = (value as? String).map { [$0] } ?? value as? [String]
        guard let names, !names.isEmpty, Set(names).count == names.count else { return nil }
        let types = names.compactMap(JSONType.init(rawValue:))
        return types.count == names.count ? types : nil
    }
    
    /// The definition a `$ref` names.
    ///
    /// - Parameter reference: The `$ref`: `#/$defs/` and one JSON pointer token, which may be percent-encoded.
    /// - Returns: The definition's name, or `nil` for any other reference.
    private static func definitionName(_ reference: String) -> String? {
        guard reference.hasPrefix(definitionsPrefix),
              let token = String(reference.dropFirst(definitionsPrefix.count)).removingPercentEncoding,
              !token.isEmpty, !token.contains("/") else { return nil }
        return token.replacingOccurrences(of: "~1", with: "/").replacingOccurrences(of: "~0", with: "~")
    }
    
    /// A key as a JSON pointer token.
    ///
    /// - Parameter name: The key.
    /// - Returns: The key with `~` and `/` escaped.
    static func escape(_ name: String) -> String {
        name.replacingOccurrences(of: "~", with: "~0").replacingOccurrences(of: "/", with: "~1")
    }
}
