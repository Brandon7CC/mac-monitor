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
/// One schema object, compiled: the subset of JSON Schema 2020-12 that Mac Monitor's telemetry schema uses. Its
/// keywords read through to ``keywords``: `node.types` is `node.keywords.types`.
///
/// Immutable once compiled, so a schema can be checked from any number of threads.
@dynamicMemberLookup
final class JSONSchemaNode {
    /// Where the node is in the schema, as a JSON pointer: `#/$defs/process/properties/cdhash`.
    let location: String
    /// Its keywords, compiled.
    let keywords: JSONSchemaCompiler.Keywords
    /// The keys of `properties`, in order, so issues come out in the same order every time.
    let propertyNames: [String]
    /// The keys of `required` that `properties` doesn't have, in order: whatever their value, they must be there.
    let unspecifiedRequired: [String]
    
    /// A node from its compiled keywords (see ``JSONSchemaCompiler``).
    ///
    /// - Parameters:
    ///   - location: Where the node is in the schema, as a JSON pointer.
    ///   - keywords: Its keywords, compiled.
    init(location: String, keywords: JSONSchemaCompiler.Keywords) {
        self.location = location
        self.keywords = keywords
        propertyNames = keywords.properties.keys.sorted()
        unspecifiedRequired = keywords.required.subtracting(keywords.properties.keys).sorted()
    }
    
    /// One of the node's keywords.
    ///
    /// - Parameter keyword: The keyword's field in ``keywords``.
    /// - Returns: Its value.
    subscript<Value>(dynamicMember keyword: KeyPath<JSONSchemaCompiler.Keywords, Value>) -> Value {
        keywords[keyPath: keyword]
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
