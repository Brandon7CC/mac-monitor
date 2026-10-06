//
//  TelemetrySchemaOriginTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - eslogger's keys and Mac Monitor's
/// Checks the schema's `x-mac-monitor-origin` marks against eslogger's own keys (`Fixtures/eslogger-keys.json`): every
/// eslogger key is marked eslogger's, with eslogger's type, every key marked eslogger's is one of eslogger's, and no
/// Mac Monitor addition is. eslogger's own records then validate in eslogger mode.
final class TelemetrySchemaOriginTests: XCTestCase {
    /// eslogger keys Mac Monitor doesn't write, and why.
    static let unwritten = ["events.exec.entitlements":
                                "eslogger on 26A5353q (message version 10) doesn't write it either"]
    
    /// Where Mac Monitor's value differs in type from eslogger's, and why.
    static let retyped: [String: String] = {
        let legacy = "null in a record from Mac Monitor before 2.2.0, which didn't keep it"
        return ["events.od_group_add.member": legacy, "events.od_group_add.member.member_value": legacy,
                "events.od_group_remove.member": legacy, "events.od_group_remove.member.member_value": legacy,
                "events.od_modify_password.account_type": legacy, "events.od_attribute_value_add.record_type": legacy,
                "definitions.process.signing_id": "null for a NULL token, or in a record from Mac Monitor before "
                    + "2.2.0, which left out an empty one"]
    }()
    
    /// eslogger's keys by scope (`envelope`, `events.exec`, `definitions.process`) and path, each with its type.
    ///
    /// - Returns: Each scope's keys, by path, with the fixture's types: `int`, `string|null`.
    /// - Throws: The error reading the fixture, or an `XCTest` failure if it isn't shaped as expected.
    private func esloggerKeys() throws -> [String: [String: String]] {
        let fixture = try fixtureObject("eslogger-keys.json")
        var scopes = ["envelope": try XCTUnwrap(fixture["envelope"] as? [String: String])]
        for group in ["events", "definitions"] {
            for (name, keys) in try XCTUnwrap(fixture[group] as? [String: [String: String]]) {
                scopes["\(group).\(name)"] = keys
            }
        }
        return scopes
    }
    
    /// The schema's keys at eslogger's paths.
    private var schemaKeys: SchemaKeyPaths {
        let (document, generator) = TelemetrySchemaSource.generate()
        return SchemaKeyPaths(document.foundation, keys: generator.keys)
    }
    
    /// A fixture path without its `?` marks, and whether its key is one eslogger leaves out.
    ///
    /// - Parameter path: The fixture's path: `destination.new_path?`.
    /// - Returns: The path, and `true` if it ended in `?`.
    private func plain(_ path: String) -> (path: String, optional: Bool) {
        (path.replacingOccurrences(of: "?", with: ""), path.hasSuffix("?"))
    }
    
    /// Every eslogger key is in the schema, at eslogger's path, marked eslogger's: the envelope, each event, and the
    /// shared process, file, stat and audit token.
    ///
    /// - Throws: The error reading the fixture.
    func testESLoggerKeysAreMarkedESLogger() throws {
        let schema = schemaKeys
        var wrong: [String] = []
        for (scope, keys) in try esloggerKeys() {
            for path in keys.keys.map({ plain($0).path }) where Self.unwritten["\(scope).\(path)"] == nil {
                switch schema.scopes[scope]?[path]?.origin {
                case .eslogger?: continue
                case .macMonitor?: wrong.append("\(scope).\(path): marked mac-monitor")
                case nil: wrong.append("\(scope).\(path): not in the schema")
                }
            }
        }
        XCTAssertEqual(wrong.sorted(), [])
    }
    
    /// Every key the schema marks eslogger's is one of eslogger's, and no Mac Monitor addition is.
    ///
    /// - Throws: The error reading the fixture.
    func testAdditionsAreNotESLoggers() throws {
        let fixture = try esloggerKeys().mapValues { Set($0.keys.map { plain($0).path }) }
        let schema = schemaKeys
        XCTAssertEqual(Set(schema.scopes.keys), Set(fixture.keys),
                       "The envelope, every event, and the named definitions")
        var wrong: [String] = []
        for (scope, keys) in schema.scopes {
            for (path, key) in keys {
                let listed = fixture[scope]?.contains(path) ?? false
                switch (key.origin, listed) {
                case (.eslogger, false): wrong.append("\(scope).\(path): marked eslogger, not eslogger's")
                case (.macMonitor, true): wrong.append("\(scope).\(path): eslogger's, marked mac-monitor")
                default: continue
                }
            }
        }
        XCTAssertEqual(wrong.sorted(), [])
    }
    
    /// Each eslogger key has eslogger's type, `null` where eslogger writes it, and is required where eslogger always
    /// writes it: `null` is also allowed for a key eslogger leaves out by message version, which Mac Monitor writes as
    /// `null`, and a key may be optional where the schema says when it's absent.
    ///
    /// - Throws: The error reading the fixture.
    func testESLoggerTypesAgree() throws {
        let schema = schemaKeys
        var wrong: [String] = [], compared = 0
        for (scope, keys) in try esloggerKeys() {
            for (fixturePath, type) in keys {
                let (path, optional) = plain(fixturePath)
                let place = "\(scope).\(path)"
                guard Self.unwritten[place] == nil, Self.retyped[place] == nil,
                      let key = schema.scopes[scope]?[path] else { continue }
                compared += 1
                let expected = Set(type.split(separator: "|").map(String.init))
                let found = schema.kinds(of: key.schema)
                if found != expected, !(optional && found == expected.union(["null"])) {
                    wrong.append("\(place): eslogger's \(type), the schema's \(found.sorted().joined(separator: "|"))")
                }
                if !optional, !key.required, key.absence == nil { wrong.append("\(place): not required") }
            }
        }
        XCTAssertGreaterThan(compared, 300)
        XCTAssertEqual(wrong.sorted(), [])
    }
    
    /// Every record of eslogger's fixtures follows the schema's eslogger fields: no eslogger key is marked Mac
    /// Monitor's, and every key the schema requires of eslogger is there. An event of a type Mac Monitor doesn't
    /// record is only that. (`eslogger-lineage.jsonl` isn't eslogger's output: its execs' `cwd` has no `stat`.)
    ///
    /// - Throws: The error reading a fixture or compiling the schema.
    func testESLoggerFixturesMatchESLoggerFields() throws {
        let validator = try generatedValidator(mode: .eslogger)
        let recorded = Set(TelemetrySchemaSource.events.map(\.name))
        var checked = 0
        for name in ["eslogger-exit.jsonl", "eslogger-open.jsonl", "eslogger-od.jsonl",
                     "eslogger-remote-thread-create.jsonl"] {
            for (index, record) in try fixtureRecords(name).enumerated() {
                let event = (record["event"] as? [String: Any])?.keys.first ?? ""
                let issues = validator.issues(in: record)
                if recorded.contains(event) {
                    checked += 1
                    XCTAssertEqual(issues.map(\.description), [], "\(name)[\(index)]")
                } else {
                    XCTAssertTrue(issues.contains { $0.problem == .unsupportedEvent(event) }, "\(name)[\(index)]")
                }
            }
        }
        XCTAssertGreaterThan(checked, 10)
    }
}
