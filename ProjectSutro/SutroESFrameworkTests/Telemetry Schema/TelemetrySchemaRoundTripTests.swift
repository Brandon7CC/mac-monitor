//
//  TelemetrySchemaRoundTripTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Opened and exported again
/// Pins the values a trace opened with File > Open Trace… exports as `null` where its record has none, and that the
/// schema allows them, so a trace opened and exported again to check it follows the schema: a process's `signing_id`
/// and an IOKit open's `parent_path` and `parent_registry_id`. Mac Monitor before 2.2.0 left them out when they were
/// empty (the registry ID with an empty path), and eslogger writes `null` for a NULL token. A value the record didn't
/// have stays unknown: the registry ID is never made up as 0.
final class TelemetrySchemaRoundTripTests: XCTestCase {
    /// A record whose value at `path` is missing or `null`.
    private struct Case {
        /// Where the record comes from, and its event.
        let label: String
        /// The record.
        let record: [String: Any]
        /// The value's key path.
        let path: [String]
    }
    
    /// The records: Mac Monitor 2.1's without the keys it left out, then eslogger's with them `null`.
    ///
    /// - Returns: The records.
    /// - Throws: The error reading a fixture.
    private func cases() throws -> [Case] {
        let exit = try fixtureObject("macmonitor-2.1-exit.jsonl")
        let process = try XCTUnwrap(exit["process"] as? [String: Any])
        let fork = try legacyRecord("fork", type: ES_EVENT_TYPE_NOTIFY_FORK, ["child": process])
        /// Message version 10, without either parent key: 2.1 wrote both or neither.
        let iokit = try legacyRecord("iokit_open", type: ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN,
                                     ["user_client_class": "AppleAPFSUserClient", "user_client_type": 0])
        let legacy = [Case(label: "2.1 exit", record: exit, path: ["process", "signing_id"]),
                      Case(label: "2.1 fork", record: fork, path: ["event", "fork", "child", "signing_id"]),
                      Case(label: "2.1 iokit_open path", record: iokit, path: ["event", "iokit_open", "parent_path"]),
                      Case(label: "2.1 iokit_open registry ID", record: iokit,
                           path: ["event", "iokit_open", "parent_registry_id"])]
        
        let lineage = try fixtureRecords("eslogger-lineage.jsonl")
        let parent: [String: Any] = ["user_client_class": "IOSurfaceRootUserClient", "user_client_type": 0,
                                     "parent_path": "/synthetic/parent", "parent_registry_id": 4_294_967_895]
        let esloggerIOKit = try esloggerRecord("iokit_open", type: Int(ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN.rawValue),
                                               parent)
        let eslogger = [Case(label: "eslogger exit", record: try fixtureObject("eslogger-exit.jsonl"),
                             path: ["process", "signing_id"]),
                        Case(label: "eslogger fork", record: lineage[0],
                             path: ["event", "fork", "child", "signing_id"]),
                        Case(label: "eslogger exec", record: lineage[1],
                             path: ["event", "exec", "target", "signing_id"]),
                        Case(label: "eslogger iokit_open", record: esloggerIOKit,
                             path: ["event", "iokit_open", "parent_path"])]
        
        return legacy.map { Case(label: $0.label, record: replacing($0.path[...], in: $0.record, with: nil),
                                 path: $0.path) }
            + eslogger.map { Case(label: $0.label, record: replacing($0.path[...], in: $0.record, with: NSNull()),
                                  path: $0.path) }
    }
    
    /// An object with the value at a key path replaced.
    ///
    /// - Parameters:
    ///   - path: The value's key path.
    ///   - object: The object.
    ///   - value: The new value, or `nil` to leave the key out.
    /// - Returns: The object.
    private func replacing(_ path: ArraySlice<String>, in object: [String: Any], with value: Any?) -> [String: Any] {
        guard let key = path.first else { return object }
        var object = object
        object[key] = path.count == 1
            ? value : replacing(path.dropFirst(), in: object[key] as? [String: Any] ?? [:], with: value)
        return object
    }
    
    /// The value at a key path.
    ///
    /// - Parameters:
    ///   - path: The key path.
    ///   - object: The object.
    /// - Returns: The value, or `nil` if a key is missing.
    private func value(at path: [String], in object: [String: Any]) -> Any? {
        path.reduce(object as Any?) { ($0 as? [String: Any])?[$1] }
    }
    
    /// Each record exports `null` where it has no value, as eslogger writes a NULL token.
    ///
    /// - Throws: The error reading a fixture or a record, or an `XCTest` failure if an export isn't an object.
    func testExportsWriteNull() throws {
        for item in try cases() {
            XCTAssertTrue(value(at: item.path, in: try export(try importRecord(item.record))) is NSNull, item.label)
        }
    }
    
    /// Each record's export, as the command line encodes it, follows the schema.
    ///
    /// - Throws: The error reading a fixture or a record, or compiling the schema.
    func testExportsFollowSchema() throws {
        let exports = try cases().map { ($0.label, exportText(try importRecord($0.record))) }
        assertValid(exports, with: try generatedValidator())
    }
    
    /// The records opened as one trace (launched-by parents named) and exported with "Export all", in JSONL and pretty
    /// JSON, follow the schema Mac Monitor ships, as `macmonitor validate` checks them. Each record's missing value,
    /// read back from the saved store, is still `null`.
    ///
    /// - Throws: The error reading a record, building the store, exporting it, or validating the files.
    func testExportedTraceFollowsSchema() throws {
        let cases = try cases()
        var messages = try cases.map { try importRecord($0.record) }
        TraceLaunchedByParents().fill(&messages)
        let store = try makeExportStore(messages)
        let validator = try TelemetryValidator.bundled()
        for pretty in [false, true] {
            /// In the order the trace was opened, as Open Trace keeps it, so each record is its case's.
            let (url, events) = try exportAll(store, pretty: pretty, from: .trace(URL(fileURLWithPath: "/trace.jsonl")))
            XCTAssertEqual(events, messages.count)
            let report = try validator.validate(traceAt: url)
            XCTAssertEqual(report.records, messages.count)
            XCTAssertTrue(report.isValid, report.report(fileName: url.lastPathComponent))
            
            /// The values saved in the store, read back: still `null`.
            var records: [[String: Any]] = []
            let reader = try TraceRecordReader(url: url)
            while case .object(let json, _)? = try reader.next() {
                records.append(try XCTUnwrap(try JSONSerialization.jsonObject(with: json) as? [String: Any]))
            }
            XCTAssertEqual(records.count, cases.count)
            for (item, record) in zip(cases, records) {
                XCTAssertTrue(value(at: item.path, in: record) is NSNull,
                              "\(item.label), \(pretty ? "pretty" : "JSONL")")
            }
        }
    }
}
