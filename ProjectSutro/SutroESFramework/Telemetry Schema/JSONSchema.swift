//
//  JSONSchema.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Origins
/// Who defines a key in Mac Monitor's telemetry: the schema's `x-mac-monitor-origin`.
enum KeyOrigin: String, Sendable {
    /// eslogger writes the key, at the same path and with the same value.
    case eslogger
    /// Mac Monitor adds the key beside eslogger's.
    case macMonitor = "mac-monitor"
}


// MARK: - Compiled schema
/// One schema object, compiled: the subset of JSON Schema 2020-12 that Mac Monitor's telemetry schema uses.
///
/// Immutable once compiled, so a schema can be checked from any number of threads.
final class JSONSchemaNode {
    /// Where the node is in the schema, as a JSON pointer: `#/$defs/process/properties/cdhash`.
    let location: String
    /// `type`: the JSON types a value may have, or `nil` for any.
    let types: [JSONType]?
    /// `const`: the one value allowed.
    let constant: JSONScalar?
    /// `enum`: the values allowed.
    let values: Set<JSONScalar>?
    /// `pattern`: what a string must contain (anchored when the pattern says so).
    let pattern: JSONPattern?
    /// `properties`: each key's schema.
    let properties: [String: JSONSchemaNode]
    /// The keys of ``properties``, in order, so issues come out in the same order every time.
    let propertyNames: [String]
    /// `required`: the keys an object must have.
    let required: Set<String>
    /// The keys of ``required`` that ``properties`` doesn't have, in order: whatever their value, they must be there.
    let unspecifiedRequired: [String]
    /// `additionalProperties: false`: an object may only have the keys of ``properties``.
    let closed: Bool
    /// `minProperties` and `maxProperties`.
    let minProperties: Int?, maxProperties: Int?
    /// `items`: every element's schema.
    let items: JSONSchemaNode?
    /// `anyOf`: the schemas of which a value must match at least one.
    let anyOf: [JSONSchemaNode]
    /// `$ref`: the name of the definition in the root's `$defs` that a value must also match.
    let reference: String?
    /// `x-mac-monitor-origin`: who defines the key this node is the schema of.
    let origin: KeyOrigin?
    
    /// A node from its compiled keywords (see ``JSONSchemaCompiler``).
    ///
    /// - Parameters:
    ///   - location: Where the node is in the schema, as a JSON pointer.
    ///   - keywords: Its keywords, compiled.
    init(location: String, keywords: JSONSchemaCompiler.Keywords) {
        self.location = location
        types = keywords.types
        constant = keywords.constant
        values = keywords.values
        pattern = keywords.pattern
        properties = keywords.properties
        propertyNames = keywords.properties.keys.sorted()
        required = keywords.required
        unspecifiedRequired = keywords.required.subtracting(keywords.properties.keys).sorted()
        closed = keywords.closed
        minProperties = keywords.minProperties
        maxProperties = keywords.maxProperties
        items = keywords.items
        anyOf = keywords.anyOf
        reference = keywords.reference
        origin = keywords.origin
    }
}


/// A compiled schema: its root, and the definitions its `$ref`s name.
struct JSONSchema {
    /// The root schema.
    let root: JSONSchemaNode
    /// The root's `$defs`, by name.
    let definitions: [String: JSONSchemaNode]
    
    /// Compile a schema.
    ///
    /// - Parameter data: The schema's JSON text.
    /// - Throws: A ``TelemetrySchemaError``: the schema isn't JSON, uses a keyword outside the supported subset or with
    ///   an invalid value, or has a `$ref` that names no definition or loops without reading into the value.
    init(data: Data) throws {
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: data)
        } catch {
            let reason = (error as NSError).userInfo["NSDebugDescription"] as? String
            throw TelemetrySchemaError.notJSON(reason ?? error.localizedDescription)
        }
        guard object is NSDictionary else { throw TelemetrySchemaError.notJSON("the top level isn't an object") }
        let compiler = JSONSchemaCompiler()
        root = try compiler.compile(object, at: "#", isRoot: true)
        definitions = compiler.definitions
        try compiler.resolveReferences()
    }
}


// MARK: - Patterns
/// A `pattern`, compiled to match as ECMA-262 does, which JSON Schema specifies: unlike ICU's, ECMA-262's `$` only
/// matches at the end of the string, never before a final line break, so each `$` that's an anchor is compiled as `\z`.
struct JSONPattern {
    /// The pattern as the schema writes it, for messages.
    let text: String
    /// The pattern, compiled.
    private let regex: NSRegularExpression
    
    /// Compile a pattern.
    ///
    /// - Parameter text: The pattern as the schema writes it.
    /// - Returns: `nil` if it isn't a regular expression.
    init?(_ text: String) {
        guard let regex = try? NSRegularExpression(pattern: Self.anchoringEnds(text)) else { return nil }
        self.text = text
        self.regex = regex
    }
    
    /// Does a string contain a match: anywhere, unless the pattern is anchored?
    ///
    /// - Parameter string: The string.
    /// - Returns: `true` if it does.
    func isFound(in string: String) -> Bool {
        regex.firstMatch(in: string, range: NSRange(string.startIndex..., in: string)) != nil
    }
    
    /// A pattern with each `$` outside a character class, and not escaped, written as ICU's `\z`.
    ///
    /// - Parameter text: The pattern.
    /// - Returns: The pattern for ICU.
    static func anchoringEnds(_ text: String) -> String {
        var result = "", escaped = false, inClass = false
        for character in text {
            switch character {
            case _ where escaped: escaped = false
            case "\\": escaped = true
            case "[": inClass = true
            case "]": inClass = false
            case "$" where !inClass:
                result += "\\z"
                continue
            default: break
            }
            result.append(character)
        }
        return result
    }
}
