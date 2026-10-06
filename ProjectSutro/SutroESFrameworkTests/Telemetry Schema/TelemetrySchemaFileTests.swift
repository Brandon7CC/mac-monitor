//
//  TelemetrySchemaFileTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The committed schema
/// Pins `Schema/mac-monitor-telemetry.schema.json`: it's what the source generates, the framework bundles it, its
/// version agrees everywhere, a released version never changes, and every key is marked and every object closed.
///
/// `ProjectSutro/Scripts/generate-telemetry-schema.sh` regenerates it: it runs ``testCommittedSchemaIsGenerated()``
/// with `MM_WRITE_SCHEMA=1`, which writes the file instead of comparing it.
final class TelemetrySchemaFileTests: XCTestCase {
    /// The environment variable that makes ``testCommittedSchemaIsGenerated()`` write the file.
    static let writeVariable = "MM_WRITE_SCHEMA"
    
    /// The released versions: each line a version and the SHA-256 of the schema released with it.
    private static var releasedVersionsURL: URL {
        repositoryURL.appendingPathComponent("Schema").appendingPathComponent("released-versions.txt")
    }
    
    /// The committed schema, parsed.
    ///
    /// - Returns: The schema's root object.
    /// - Throws: The error reading or parsing the file.
    private func committedSchema() throws -> [String: Any] {
        let data = try Data(contentsOf: Self.schemaFileURL)
        return try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    }
    
    /// The committed schema is what the source generates, byte for byte. With `MM_WRITE_SCHEMA=1` it's written instead.
    ///
    /// - Throws: The error reading or writing the file.
    func testCommittedSchemaIsGenerated() throws {
        let generated = TelemetrySchemaSource.text
        if ProcessInfo.processInfo.environment[Self.writeVariable] == "1" {
            try FileManager.default.createDirectory(at: Self.schemaFileURL.deletingLastPathComponent(),
                                                    withIntermediateDirectories: true)
            try Data(generated.utf8).write(to: Self.schemaFileURL, options: .atomic)
            return
        }
        let committed = (try? String(contentsOf: Self.schemaFileURL, encoding: .utf8)) ?? ""
        guard committed != generated else { return }
        let old = committed.components(separatedBy: "\n"), new = generated.components(separatedBy: "\n")
        let line = zip(old, new).enumerated().first { $1.0 != $1.1 }?.offset ?? min(old.count, new.count)
        XCTFail("""
            Schema/\(TelemetrySchema.fileName) isn't what the source generates: line \(line + 1) is
              \(line < old.count ? old[line] : "(the end of the file)")
            and should be
              \(line < new.count ? new[line] : "(the end of the file)")
            Regenerate it with ProjectSutro/Scripts/generate-telemetry-schema.sh.
            """)
    }
    
    /// The framework bundles the committed schema: a missing or stale resource fails.
    ///
    /// - Throws: The error reading the schema.
    func testBundledSchemaIsCommitted() throws {
        XCTAssertEqual(try TelemetrySchema.data(), try Data(contentsOf: Self.schemaFileURL))
    }
    
    /// The schema's `$id`, title and `telemetry_version` constant name the framework's version, and every record must
    /// carry it.
    ///
    /// - Throws: The error reading the schema.
    func testVersionAgrees() throws {
        let schema = try committedSchema()
        XCTAssertEqual(schema["$id"] as? String, TelemetrySchema.identifier)
        XCTAssertEqual(schema["$schema"] as? String, "https://json-schema.org/draft/2020-12/schema")
        XCTAssertTrue((schema["title"] as? String)?.hasSuffix(" \(TelemetrySchema.version)") ?? false)
        let property = (schema["properties"] as? [String: Any])?[TelemetrySchema.versionKey] as? [String: Any]
        XCTAssertEqual(property?["const"] as? String, TelemetrySchema.version)
        XCTAssertTrue((schema["required"] as? [String] ?? []).contains(TelemetrySchema.versionKey))
        XCTAssertEqual(try TelemetryValidator.bundled().schemaVersion, TelemetrySchema.version)
    }
    
    /// A released version's schema never changes: if `Schema/released-versions.txt` lists the current version, the
    /// file must have the hash it was released with. No version listed is newer than the current one.
    ///
    /// - Throws: The error reading the files.
    func testReleasedSchemasAreFrozen() throws {
        let text = (try? String(contentsOf: Self.releasedVersionsURL, encoding: .utf8)) ?? ""
        let hash = try Self.schemaSHA256
        let lines = text.split(separator: "\n").filter { !$0.hasPrefix("#") && !$0.allSatisfy(\.isWhitespace) }
        for line in lines {
            let fields = line.split(separator: " ").map(String.init)
            XCTAssertEqual(fields.count, 2, "Expected \"<version> <sha256>\": \(line)")
            guard let version = fields.first, let released = fields.last else { continue }
            XCTAssertFalse(Self.isNewer(version, than: TelemetrySchema.version),
                           "\(version) is newer than the schema's")
            if version == TelemetrySchema.version {
                XCTAssertEqual(hash, released,
                               "Telemetry \(version) was released with another schema: bump the version")
            }
        }
    }
    
    /// Every keyword of the schema is in the validator's subset.
    func testValidatorLoadsSchema() {
        XCTAssertNoThrow(try TelemetryValidator.bundled())
        XCTAssertNoThrow(try TelemetryValidator.bundled(mode: .eslogger))
    }
    
    /// Every property says whose it is, and every one of Mac Monitor's says what it holds; every object is closed.
    /// Every object is checked, nested in a property of any name (`type` included), an array or an alternative.
    ///
    /// - Throws: The error reading the schema.
    func testEveryKeyIsMarkedAndEveryObjectClosed() throws {
        var unmarked: [String] = [], undescribed: [String] = [], open: [String] = []
        let parts = SchemaParts(try committedSchema())
        XCTAssertGreaterThan(parts.objects.count, TelemetrySchemaSource.events.count)
        for object in parts.objects {
            if !object.closed { open.append(object.location) }
            for (key, property) in object.properties {
                let origin = property["x-mac-monitor-origin"] as? String
                if !["eslogger", "mac-monitor"].contains(origin ?? "") { unmarked.append("\(object.location).\(key)") }
                if origin == "mac-monitor", property["description"] == nil {
                    undescribed.append("\(object.location).\(key)")
                }
            }
        }
        XCTAssertEqual(unmarked, [], "Keys without an origin")
        XCTAssertEqual(undescribed, [], "Mac Monitor keys without a description")
        XCTAssertEqual(open, [], "Objects that allow other keys")
    }
    
    /// The walk reaches every object's schema, however it's nested: in a property named like a keyword, an array's
    /// items, an alternative, or a definition; a keyword's value that isn't a schema is never walked.
    ///
    /// - Throws: The error parsing the schema.
    func testSchemaPartsReachEveryObject() throws {
        let schema = """
            {"properties": {"type": {"type": "object", "properties": {"a": {}}},
                            "list": {"items": {"anyOf": [{"type": "null"}, {"properties": {"b": {}}}]}}},
             "enum": [{"properties": {"c": {}}}], "$defs": {"thing": {"properties": {"d": {}}}}}
            """
        let parts = SchemaParts(try JSONSerialization.jsonObject(with: Data(schema.utf8)))
        XCTAssertEqual(parts.objects.map(\.location), ["#", "#/properties/list/items/anyOf/1", "#/properties/type",
                                                        "#/$defs/thing"])
    }
    
    /// The writer's text parses back to the document it wrote, and writing twice gives the same bytes.
    ///
    /// - Throws: The error parsing the text.
    func testWriterRoundTrips() throws {
        let document = TelemetrySchemaSource.generate().document
        let text = SchemaJSONWriter.text(document)
        let parsed = try JSONSerialization.jsonObject(with: Data(text.utf8))
        XCTAssertEqual(parsed as? NSDictionary, document.foundation as? NSDictionary)
        XCTAssertEqual(text, TelemetrySchemaSource.text)
        let tricky = OrderedJSON.object([.init(key: "a/b", value: .string("q\"\\\n\t\u{01}/é"))])
        let trickyText = Data(SchemaJSONWriter.text(tricky).utf8)
        XCTAssertEqual(try JSONSerialization.jsonObject(with: trickyText) as? NSDictionary,
                       tricky.foundation as? NSDictionary)
        XCTAssertTrue(SchemaJSONWriter.text(tricky).contains("\"a/b\""))
    }
    
    /// Is one semantic version newer than another?
    ///
    /// - Parameters:
    ///   - version: A version: `1.2.0`.
    ///   - other: Another.
    /// - Returns: `true` if `version` is newer.
    private static func isNewer(_ version: String, than other: String) -> Bool {
        let parts = { (text: String) in text.split(separator: ".").map { Int($0) ?? 0 } }
        return parts(other).lexicographicallyPrecedes(parts(version))
    }
}
