//
//  TelemetryValidatorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The validator's subset of JSON Schema
/// Pins what ``TelemetryValidator`` checks, on small schemas of its own: each keyword of the subset, the keywords it
/// rejects, eslogger mode, and the wording of each issue, which the app and the command line share.
final class TelemetryValidatorTests: XCTestCase {
    /// A validator for a schema.
    ///
    /// - Parameters:
    ///   - schema: The schema's JSON text.
    ///   - mode: Which keys are checked.
    /// - Returns: The validator.
    /// - Throws: The error compiling the schema.
    private func validator(_ schema: String, mode: TelemetryValidator.Mode = .macMonitor) throws -> TelemetryValidator {
        try TelemetryValidator(schema: Data(schema.utf8), mode: mode)
    }
    
    /// The issues of a record, as text.
    ///
    /// - Parameters:
    ///   - record: The record's JSON text.
    ///   - schema: The schema's JSON text.
    ///   - mode: Which keys are checked.
    /// - Returns: Each issue's description.
    /// - Throws: The error compiling the schema.
    private func issues(_ record: String, against schema: String,
                        mode: TelemetryValidator.Mode = .macMonitor) throws -> [String] {
        try validator(schema, mode: mode).issues(inRecord: Data(record.utf8)).map(\.description)
    }
    
    /// The issues of one value, checked as the record's key `v`.
    ///
    /// - Parameters:
    ///   - value: The value's JSON text.
    ///   - property: The schema of `v`.
    /// - Returns: Each issue's description.
    /// - Throws: The error compiling the schema.
    private func issues(of value: String, against property: String) throws -> [String] {
        try issues("{\"v\": \(value)}", against: "{\"type\": \"object\", \"properties\": {\"v\": \(property)}}")
    }
    
    /// The error compiling a schema.
    ///
    /// - Parameter schema: The schema's JSON text.
    /// - Returns: The error, or `nil` if it compiles.
    private func loadError(_ schema: String) -> TelemetrySchemaError? {
        do {
            _ = try validator(schema)
            return nil
        } catch {
            return error as? TelemetrySchemaError
        }
    }
    
    // MARK: Types
    
    /// Each type name accepts its own values and no other.
    ///
    /// - Throws: The error compiling a schema.
    func testEachTypeName() throws {
        let samples = ["null": "null", "boolean": "false", "integer": "-3", "number": "2.5", "string": "\"s\"",
                       "array": "[1]", "object": "{\"a\": 1}"]
        for (type, value) in samples {
            for (other, sample) in samples {
                let found = try issues(of: sample, against: "{\"type\": \"\(type)\"}")
                let allowed = other == type || (type == "number" && other == "integer")
                XCTAssertEqual(found.isEmpty, allowed, "\(sample) against \(type): \(found)")
            }
            guard type != "null" else { continue }
            XCTAssertEqual(try issues(of: value, against: "{\"type\": [\"\(type)\", \"null\"]}"), [])
            XCTAssertEqual(try issues(of: "null", against: "{\"type\": [\"\(type)\", \"null\"]}"), [])
        }
    }
    
    /// A Boolean is never an integer, and an integer is never a Boolean.
    ///
    /// - Throws: The error compiling a schema.
    func testBooleanIsNeverAnInteger() throws {
        XCTAssertEqual(try issues(of: "true", against: "{\"type\": \"integer\"}"), ["v: expected integer, found true"])
        XCTAssertEqual(try issues(of: "1", against: "{\"type\": \"boolean\"}"), ["v: expected boolean, found 1"])
    }
    
    /// A number without a fraction is an integer, however it's written or however large it is.
    ///
    /// - Throws: The error compiling a schema.
    func testIntegersByValue() throws {
        let integer = "{\"type\": \"integer\"}"
        for value in ["1.0", "1e3", "18446744073709551615", "1152921500312603095", "100000000000000000000000000000"] {
            XCTAssertEqual(try issues(of: value, against: integer), [], value)
        }
        XCTAssertEqual(try issues(of: "1.5", against: integer), ["v: expected integer, found 1.5"])
    }
    
    // MARK: Values
    
    /// `enum` and `const` compare by value and JSON type: `1` isn't `true`.
    ///
    /// - Throws: The error compiling a schema.
    func testEnumAndConstAreTypeAware() throws {
        XCTAssertEqual(try issues(of: "true", against: "{\"enum\": [1, 2]}"),
                       ["v: true isn't one of the schema's values"])
        XCTAssertEqual(try issues(of: "2", against: "{\"enum\": [1, 2]}"), [])
        XCTAssertEqual(try issues(of: "1", against: "{\"const\": true}"), ["v: 1 isn't true"])
        XCTAssertEqual(try issues(of: "true", against: "{\"const\": 1}"), ["v: true isn't 1"])
        XCTAssertEqual(try issues(of: "\"b\"", against: "{\"enum\": [\"a\", \"b\"]}"), [])
        XCTAssertEqual(try issues(of: "\"c\"", against: "{\"enum\": [\"a\", \"b\"]}"),
                       ["v: \"c\" isn't one of the schema's values"])
        XCTAssertEqual(try issues(of: "\"1.0.1\"", against: "{\"const\": \"1.0.0\"}"), ["v: \"1.0.1\" isn't \"1.0.0\""])
    }
    
    /// A pattern is searched for anywhere in the string unless it's anchored, as JSON Schema says.
    ///
    /// - Throws: The error compiling a schema.
    func testPatternSearchesUnlessAnchored() throws {
        XCTAssertEqual(try issues(of: "\"abbc\"", against: "{\"pattern\": \"b+\"}"), [])
        let cdhash = "{\"pattern\": \"^[0-9A-F]{40}$\"}", hex = String(repeating: "0A", count: 20)
        XCTAssertEqual(try issues(of: "\"\(hex)\"", against: cdhash), [])
        XCTAssertEqual(try issues(of: "\"0df5\"", against: cdhash), ["v: \"0df5\" doesn't match ^[0-9A-F]{40}$"])
        XCTAssertEqual(try issues(of: "12", against: cdhash), [], "A pattern only constrains strings")
    }
    
    /// `$` matches only at the end of the string, as in ECMA-262, which JSON Schema's patterns follow: never before a
    /// final line break, as ICU's would. A `$` in a character class or escaped is the character.
    ///
    /// - Throws: The error compiling a schema.
    func testDollarMatchesOnlyAtTheEnd() throws {
        let cdhash = "{\"pattern\": \"^[0-9A-F]{40}$\"}", hex = String(repeating: "0A", count: 20)
        XCTAssertEqual(try issues(of: "\"\(hex)\\n\"", against: cdhash),
                       ["v: \"\(hex)\\n\" doesn't match ^[0-9A-F]{40}$"])
        for ending in ["\\r\\n", "\\r", "\\u2028"] {
            XCTAssertEqual(try issues(of: "\"\(hex)\(ending)\"", against: cdhash).count, 1, ending)
        }
        XCTAssertEqual(try issues(of: "\"a$\"", against: #"{"pattern": "^a[$]$"}"#), [])
        XCTAssertEqual(try issues(of: "\"a$b\"", against: #"{"pattern": "^a\\$b$"}"#), [])
        XCTAssertEqual(try issues(of: "\"ab\"", against: #"{"pattern": "a$|b"}"#), [])
        XCTAssertEqual(try issues(of: "\"ac\"", against: #"{"pattern": "a$|b"}"#), ["v: \"ac\" doesn't match a$|b"])
    }
    
    // MARK: Objects and arrays
    
    /// A missing key's path is the key's own, and so is a key the schema doesn't have.
    ///
    /// - Throws: The error compiling the schema.
    func testRequiredAndClosedObjects() throws {
        let schema = """
            {"properties": {"a": {"type": "object", "properties": {"b": {"type": "string"}, "c": {"type": "string"}},
             "required": ["b"], "additionalProperties": false}}}
            """
        XCTAssertEqual(try issues("{\"a\": {\"extra\": 1, \"c\": \"x\"}}", against: schema),
                       ["a.b: missing", "a.extra: not in the schema"])
        XCTAssertEqual(try issues("{\"a\": {\"b\": \"x\"}}", against: schema), [])
    }
    
    /// A required key that `properties` doesn't describe must be there too, whatever its value.
    ///
    /// - Throws: The error compiling a schema.
    func testRequiredKeysWithoutSchemas() throws {
        XCTAssertEqual(try issues("{}", against: "{\"type\": \"object\", \"required\": [\"a\"]}"), ["a: missing"])
        let described = "{\"properties\": {\"b\": {}}, \"required\": [\"a\", \"b\"]}"
        XCTAssertEqual(try issues("{\"b\": 1}", against: described), ["a: missing"])
        XCTAssertEqual(try issues("{\"a\": [], \"b\": 1}", against: described), [])
        XCTAssertEqual(try issues("{\"v\": {}}", against: "{\"properties\": {\"v\": {\"required\": [\"a\"]}}}"),
                       ["v.a: missing"])
    }
    
    /// An element's path carries its index, and keys that aren't identifiers are quoted, as are identifiers longer
    /// than a quoted value, which are cut.
    ///
    /// - Throws: The error compiling the schema.
    func testPathsCarryIndexesAndQuotedKeys() throws {
        XCTAssertEqual(try issues(of: "[\"a\", \"b\", 3]", against: "{\"items\": {\"type\": \"string\"}}"),
                       ["v[2]: expected string, found 3"])
        let schema = "{\"properties\": {\"v\": {\"properties\": {\"a b\": {\"type\": \"string\"}}}}}"
        XCTAssertEqual(try issues("{\"v\": {\"a b\": 1}}", against: schema), ["v[\"a b\"]: expected string, found 1"])
        
        let longest = String(repeating: "k", count: JSONText.maxQuoted), closed = "{\"additionalProperties\": false}"
        XCTAssertEqual(try issues("{\"\(longest)\": 1}", against: closed), ["\(longest): not in the schema"])
        XCTAssertEqual(try issues("{\"\(longest)k\": 1}", against: closed), ["[\"\(longest)…\"]: not in the schema"])
    }
    
    /// The event dispatcher holds exactly one event, and an event Mac Monitor doesn't record is named as such.
    ///
    /// - Throws: The error compiling the schema.
    func testEventDispatcher() throws {
        let schema = """
            {"properties": {"event": {"$ref": "#/$defs/event"}}, "$defs": {"event": {"type": "object",
             "properties": {"exit": {"type": "object"}, "fork": {"type": "object"}}, "additionalProperties": false,
             "minProperties": 1, "maxProperties": 1}}}
            """
        XCTAssertEqual(try issues("{\"event\": {\"exit\": {}}}", against: schema), [])
        XCTAssertEqual(try issues("{\"event\": {}}", against: schema), ["event: has 0 keys, expected 1"])
        XCTAssertEqual(try issues("{\"event\": {\"exit\": {}, \"fork\": {}}}", against: schema),
                       ["event: has 2 keys, expected 1"])
        XCTAssertEqual(try issues("{\"event\": {\"od_attribute_set\": {}}}", against: schema),
                       ["event.od_attribute_set: Mac Monitor doesn't record od_attribute_set events"])
        
        /// A name that isn't a short identifier is quoted, and cut, as the path quotes it: it stays on one line.
        XCTAssertEqual(try issues("{\"event\": {\"a\\nb\": {}}}", against: schema),
                       [#"event["a\nb"]: Mac Monitor doesn't record "a\nb" events"#])
        let long = String(repeating: "e", count: 1 << 20), cut = String(repeating: "e", count: JSONText.maxQuoted)
        XCTAssertEqual(try issues("{\"event\": {\"\(long)\": {}}}", against: schema),
                       ["event[\"\(cut)…\"]: Mac Monitor doesn't record \"\(cut)…\" events"])
    }
    
    // MARK: Alternatives and references
    
    /// A nullable object accepts `null`; a broken object reports what's wrong inside it; a value of neither type
    /// lists the types allowed.
    ///
    /// - Throws: The error compiling the schema.
    func testAnyOf() throws {
        let schema = """
            {"properties": {"v": {"anyOf": [{"type": "null"}, {"$ref": "#/$defs/thing"}]}},
             "$defs": {"thing": {"type": "object", "properties": {"a": {"type": "integer"}}, "required": ["a"]}}}
            """
        XCTAssertEqual(try issues("{\"v\": null}", against: schema), [])
        XCTAssertEqual(try issues("{\"v\": {\"a\": 1}}", against: schema), [])
        XCTAssertEqual(try issues("{\"v\": {\"a\": \"x\"}}", against: schema), ["v.a: expected integer, found \"x\""])
        XCTAssertEqual(try issues("{\"v\": \"s\"}", against: schema), ["v: expected null or object, found \"s\""])
    }
    
    /// References resolve, a reference to nothing or a loop of references fails to load, and a schema that recurses
    /// into its value checks every level.
    ///
    /// - Throws: The error compiling a schema.
    func testReferences() throws {
        XCTAssertEqual(loadError("{\"properties\": {\"v\": {\"$ref\": \"#/$defs/nope\"}}}"),
                       .unresolvedReference("#/$defs/nope", at: "#/properties/v"))
        XCTAssertEqual(loadError("{\"properties\": {\"v\": {\"$ref\": \"other.json#/x\"}}}"),
                       .invalidKeyword("$ref", at: "#/properties/v"))
        let loop = loadError(##"{"$defs": {"a": {"$ref": "#/$defs/b"}, "b": {"anyOf": [{"$ref": "#/$defs/a"}]}}}"##)
        guard case .referenceCycle? = loop else {
            return XCTFail("Expected a reference cycle, found \(String(describing: loop))")
        }
        
        let tree = """
            {"$ref": "#/$defs/node", "$defs": {"node": {"type": "object",
             "properties": {"child": {"$ref": "#/$defs/node"}}, "additionalProperties": false}}}
            """
        XCTAssertEqual(try issues("{\"child\": {\"child\": {}}}", against: tree), [])
        XCTAssertEqual(try issues("{\"child\": {\"child\": 3}}", against: tree),
                       ["child.child: expected object, found 3"])
    }
    
    // MARK: The supported subset
    
    /// Keywords outside the subset are rejected, by name and JSON pointer, so no constraint is silently ignored.
    func testUnsupportedKeywordsAreRejected() {
        XCTAssertEqual(loadError("{\"oneOf\": [{\"type\": \"object\"}]}"), .unsupportedKeyword("oneOf", at: "#"))
        XCTAssertEqual(loadError("{\"properties\": {\"v\": {\"if\": {}}}}"),
                       .unsupportedKeyword("if", at: "#/properties/v"))
        XCTAssertEqual(loadError("{\"patternProperties\": {\"^a\": {}}}"),
                       .unsupportedKeyword("patternProperties", at: "#"))
        XCTAssertEqual(loadError("{\"properties\": {\"v\": {\"minimum\": 0}}}"),
                       .unsupportedKeyword("minimum", at: "#/properties/v"))
        XCTAssertEqual(loadError("{\"properties\": {\"v\": {\"additionalProperties\": {\"type\": \"string\"}}}}"),
                       .unsupportedKeyword("additionalProperties", at: "#/properties/v"))
        XCTAssertEqual(loadError("{\"properties\": {\"v\": {\"$defs\": {}}}}"),
                       .unsupportedKeyword("$defs", at: "#/properties/v"))
        XCTAssertEqual(loadError("{\"$schema\": \"http://json-schema.org/draft-07/schema#\"}"),
                       .invalidKeyword("$schema", at: "#"))
        XCTAssertEqual(loadError("{\"type\": \"text\"}"), .invalidKeyword("type", at: "#"))
        XCTAssertEqual(loadError("{\"properties\": {\"v\": {\"x-mac-monitor-origin\": \"apple\"}}}"),
                       .invalidKeyword("x-mac-monitor-origin", at: "#/properties/v"))
        XCTAssertEqual(loadError("[]"), .notJSON("the top level isn't an object"))
    }
    
    /// A schema with several problems always reports the same one, the first in the order of its keys, whatever order
    /// `JSONSerialization` gives them in.
    func testLoadErrorsFollowTheSchemasOrder() {
        for _ in 0..<5 {
            XCTAssertEqual(loadError(#"{"properties": {"b": {"minimum": 0}, "c": {"if": {}}, "a": {"maximum": 1}}}"#),
                           .unsupportedKeyword("maximum", at: "#/properties/a"))
            XCTAssertEqual(loadError(##"{"$defs": {"b": {"$ref": "#/$defs/y"}, "a": {"$ref": "#/$defs/x"}}}"##),
                           .unresolvedReference("#/$defs/x", at: "#/$defs/a"))
        }
    }
    
    /// Annotations and `x-` keywords load, and don't constrain anything.
    ///
    /// - Throws: The error compiling the schema.
    func testAnnotationsAreAccepted() throws {
        let schema = """
            {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "urn:example", "title": "t",
             "description": "d", "$comment": "c", "properties": {"v": {"format": "date-time", "examples": ["x"],
             "default": "x", "deprecated": false, "x-anything": {"a": 1}, "x-mac-monitor-origin": "eslogger"}}}
            """
        XCTAssertEqual(try issues("{\"v\": 12}", against: schema), [])
    }
    
    // MARK: eslogger mode
    
    /// In eslogger mode Mac Monitor's keys aren't required, and one that's present is an issue.
    ///
    /// - Throws: The error compiling the schema.
    func testESLoggerMode() throws {
        let schema = """
            {"properties": {"a": {"type": "integer", "x-mac-monitor-origin": "eslogger"},
             "b": {"type": "integer", "x-mac-monitor-origin": "mac-monitor"}}, "required": ["a", "b"]}
            """
        XCTAssertEqual(try issues("{\"a\": 1}", against: schema, mode: .eslogger), [])
        XCTAssertEqual(try issues("{\"a\": 1, \"b\": 2}", against: schema, mode: .eslogger),
                       ["b: Mac Monitor field in an eslogger record"])
        XCTAssertEqual(try issues("{}", against: schema, mode: .eslogger), ["a: missing"])
        XCTAssertEqual(try issues("{\"a\": 1}", against: schema), ["b: missing"])
    }
    
    // MARK: Wording
    
    /// Each problem's words, with and without a line, as the app and the command line show them.
    func testIssueText() {
        let path = InstancePath.index(.key(.key(.key(.root, "event"), "exec"), "args"), 2)
        /// An issue with a problem, at `event.exec.args[2][0]`, as text.
        func text(_ problem: TelemetryIssue.Problem, _ value: Any? = nil, line: Int? = 812) -> String {
            TelemetryIssue(line: line, path: .index(path, 0), schemaLocation: "#", problem: problem,
                           value: value).description
        }
        XCTAssertEqual(text(.missing), "line 812: event.exec.args[2][0]: missing")
        XCTAssertEqual(text(.unexpected, line: nil), "event.exec.args[2][0]: not in the schema")
        XCTAssertEqual(text(.unsupportedEvent("od_delete_user")),
                       "line 812: event.exec.args[2][0]: Mac Monitor doesn't record od_delete_user events")
        XCTAssertEqual(text(.type(expected: ["string", "null"], found: "array"), [1]),
                       "line 812: event.exec.args[2][0]: expected string or null, found an array")
        XCTAssertEqual(text(.notConst("\"1.0.0\""), "9.9.9"),
                       "line 812: event.exec.args[2][0]: \"9.9.9\" isn't \"1.0.0\"")
        XCTAssertEqual(text(.notInEnum, 7), "line 812: event.exec.args[2][0]: 7 isn't one of the schema's values")
        XCTAssertEqual(text(.pattern("^[0-9]{4}$"), "x/y"),
                       "line 812: event.exec.args[2][0]: \"x/y\" doesn't match ^[0-9]{4}$")
        XCTAssertEqual(text(.propertyCount(found: 2, minimum: 1, maximum: 1)),
                       "line 812: event.exec.args[2][0]: has 2 keys, expected 1")
        XCTAssertEqual(text(.noBranch(expected: ["null", "object"], found: "string"), "s"),
                       "line 812: event.exec.args[2][0]: expected null or object, found \"s\"")
        XCTAssertEqual(text(.macMonitorFieldInESLogger),
                       "line 812: event.exec.args[2][0]: Mac Monitor field in an eslogger record")
        let whole = TelemetryIssue(line: 3, path: .root, schemaLocation: "#", problem: .malformedRecord)
        XCTAssertEqual(whole.description, "line 3: incomplete or malformed JSON")
        let unreadable = TelemetryIssue(line: nil, path: .root, schemaLocation: "#", problem: .notJSON("bad"))
        XCTAssertEqual(unreadable.description, "not JSON (bad)")
        let kind = TelemetryIssue(line: 9, path: .index(path, 4), schemaLocation: "#", problem: .pattern("^a$"),
                                  value: "b").kind
        XCTAssertEqual(kind.description, "event.exec.args[][]: doesn't match ^a$")
    }
}
