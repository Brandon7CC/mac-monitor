//
//  RecordKeyPathsNetworkTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - A network flow's key paths
/// Pins what the JSON tab's key path bar reads for a network flow's record: every key path the record has, described
/// as the schema's network definition describes it, with its process as a `flow_process` rather than an Endpoint
/// Security process.
final class RecordKeyPathsNetworkTests: XCTestCase {
    /// - Parameter record: A synthetic record.
    /// - Returns: Its outline, as the JSON tab shows the record.
    private func outline(_ record: SyntheticCorpus.Record) throws -> JSONOutline {
        let encoder = ExportEncoder(model: try XCTUnwrap(ExportEncoder.model), pretty: true)
        return JSONOutline(String(decoding: encoder.line(for: record.message), as: UTF8.self))
    }

    /// Every value of every network record has a key path the network definition has, and the keys a rule on a flow
    /// reads most are described.
    func testEveryKeyPathOfAFlowIsKnown() throws {
        var seen: Set<String> = []
        for record in SyntheticCorpus.networkRecords() {
            let outline = try outline(record)
            XCTAssertTrue(RecordKeyPaths.isNetworkRecord(outline), record.label)
            for value in outline.values where !value.keyPath.isEmpty {
                XCTAssertNotNil(RecordKeyPaths.shared.node(value.keyPath, inNetworkRecord: true),
                                "\(record.label): \(value.keyPath)")
                seen.insert(value.keyPath)
            }
        }
        let described = ["event.new_flow.remote_hostname", "event.flow_closed.bytes_inbound_count",
                         "event.new_flow.source_app.signing_id", "event.flow_closed.remote_endpoint.port",
                         "process.signing_id", "process.executable.path", "process.pid", "context"]
        for path in described {
            XCTAssertTrue(seen.contains(path), path)
            XCTAssertNotNil(RecordKeyPaths.shared.node(path, inNetworkRecord: true)?.summary, path)
        }
    }

    /// A flow's process keys are described as a `flow_process`'s, not as an Endpoint Security process's, and keys only
    /// an Endpoint Security process has aren't a flow's.
    func testAFlowsProcessIsAFlowProcess() {
        let keyPaths = RecordKeyPaths.shared
        let flow = keyPaths.node("process.signing_id", inNetworkRecord: true)?.summary
        XCTAssertEqual(flow,
                       "The process's signing ID. Absent when the code is unsigned, or its signature wasn't read.")
        XCTAssertNotEqual(keyPaths.node("process.signing_id", inNetworkRecord: false)?.summary, flow)
        XCTAssertEqual(keyPaths.node("process.pid", inNetworkRecord: true)?.summary,
                       "The process ID: 0 for the kernel.")
        XCTAssertNil(keyPaths.node("process.cdhash", inNetworkRecord: true))
        XCTAssertNotNil(keyPaths.node("process.cdhash", inNetworkRecord: false))
        XCTAssertNil(keyPaths.node("es_event_type", inNetworkRecord: true))
        XCTAssertNotNil(keyPaths.node("es_event_type", inNetworkRecord: false))
    }

    /// No Endpoint Security record reads as a network record.
    func testEndpointSecurityRecordsAreNotNetworkRecords() throws {
        for record in try SyntheticCorpus.records() where record.message.event.macMonitorEvent == nil {
            XCTAssertFalse(RecordKeyPaths.isNetworkRecord(try outline(record)), record.label)
        }
    }
}
