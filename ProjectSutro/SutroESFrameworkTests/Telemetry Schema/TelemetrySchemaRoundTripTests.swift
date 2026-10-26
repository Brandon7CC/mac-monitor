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
/// and an IOKit open's `parent_path` and `parent_registry_id`. Mac Monitor before 3.0.0 left them out when they were
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
        let path: [JSONStep]
    }
    
    /// The records: Mac Monitor 2.1's without the keys it left out, then eslogger's with them `null`.
    ///
    /// - Returns: The records.
    /// - Throws: The error reading a fixture.
    private func cases() throws -> [Case] {
        let exit = try fixtureObject("macmonitor-2.1-exit.jsonl")
        let process = try XCTUnwrap(exit["process"] as? [String: Any])
        let fork = try legacyRecord(ES_EVENT_TYPE_NOTIFY_FORK, ["child": process])
        /// Message version 10, without either parent key: 2.1 wrote both or neither.
        let iokit = try legacyRecord(ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN,
                                     ["user_client_class": "AppleAPFSUserClient", "user_client_type": 0])
        let legacy = [Case(label: "2.1 exit", record: exit, path: ["process", "signing_id"]),
                      Case(label: "2.1 fork", record: fork, path: ["event", "fork", "child", "signing_id"]),
                      Case(label: "2.1 iokit_open path", record: iokit, path: ["event", "iokit_open", "parent_path"]),
                      Case(label: "2.1 iokit_open registry ID", record: iokit,
                           path: ["event", "iokit_open", "parent_registry_id"])]
        
        let lineage = try fixtureRecords("eslogger-lineage.jsonl")
        let parent: [String: Any] = ["user_client_class": "IOSurfaceRootUserClient", "user_client_type": 0,
                                     "parent_path": "/synthetic/parent", "parent_registry_id": 4_294_967_895]
        let esloggerIOKit = try esloggerRecord(ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, parent)
        let eslogger = [Case(label: "eslogger exit", record: try fixtureObject("eslogger-exit.jsonl"),
                             path: ["process", "signing_id"]),
                        Case(label: "eslogger fork", record: lineage[0],
                             path: ["event", "fork", "child", "signing_id"]),
                        Case(label: "eslogger exec", record: lineage[1],
                             path: ["event", "exec", "target", "signing_id"]),
                        Case(label: "eslogger iokit_open", record: esloggerIOKit,
                             path: ["event", "iokit_open", "parent_path"])]
        
        return [(legacy, nil), (eslogger, NSNull())].flatMap { cases, missing in
            cases.map { item in
                var record = item.record
                record[path: item.path] = missing
                return Case(label: item.label, record: record, path: item.path)
            }
        }
    }
    
    /// Each record exports `null` where it has no value, as eslogger writes a NULL token.
    func testExportsWriteNull() throws {
        for item in try cases() {
            XCTAssertTrue(try export(try importRecord(item.record))[path: item.path] is NSNull, item.label)
        }
    }
    
    /// Each record's export, as the command line encodes it, follows the schema.
    func testExportsFollowSchema() throws {
        let exports = try cases().map { ($0.label, exportText(try importRecord($0.record))) }
        assertValid(exports, with: try generatedValidator())
    }
    
    /// The records opened as one trace (launched-by parents named) and exported with "Export all", in JSONL and pretty
    /// JSON, follow the schema Mac Monitor ships, as `macmonitor validate` checks them. Each record's missing value,
    /// read back from the saved store, is still `null`.
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
                records.append(try jsonObject(json))
            }
            XCTAssertEqual(records.count, cases.count)
            for (item, record) in zip(cases, records) {
                XCTAssertTrue(record[path: item.path] is NSNull, "\(item.label), \(pretty ? "pretty" : "JSONL")")
            }
        }
    }
}
