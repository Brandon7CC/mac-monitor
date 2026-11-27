//
//  NetworkRecordExportTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Network records
/// Pins a network flow's record as the store exports it: Mac Monitor's own envelope, with none of eslogger's keys,
/// each event's keys, and its process as `flow_process`. A key the flow doesn't have is left out, never written as
/// `null`.
final class NetworkRecordExportTests: XCTestCase {
    /// The keys every network record has.
    private static let envelope: Set<String> = ["telemetry_version", "time", "mach_time", "macOS", "sip_status",
                                                "boot_session_uuid", "sensor_id", "process", "event", "context",
                                                "target_path"]
    /// The keys a full flow's event has.
    private static let flowKeys: Set<String> = ["identifier", "remote_endpoint", "remote_address_scope",
                                                "local_endpoint", "remote_hostname", "url", "first_party_site",
                                                "direction", "socket_family",
                                                "socket_family_string", "socket_type", "socket_type_string",
                                                "socket_protocol", "socket_protocol_string", "start_time"]
    /// The keys a live process has.
    private static let processKeys: Set<String> = ["pid", "audit_token", "audit_token_string", "euid", "euid_human",
                                                   "ppid", "group_id", "session_id", "executable", "signing_id",
                                                   "team_id", "codesigning_type"]

    /// - Parameter record: A flow.
    /// - Returns: Its record, as the store exports it.
    private func record(_ record: FlowRecord) throws -> [String: Any] {
        try export(SyntheticFlows.message(record))
    }

    /// A network record has only Mac Monitor's envelope: no version, sequence numbers, thread, action, event_type or
    /// es_event_type.
    func testTheEnvelope() throws {
        for kind in [FlowRecord.Kind.opened, .closed] {
            let exported = try record(SyntheticFlows.record(kind))
            XCTAssertEqual(Set(exported.keys), Self.envelope)
            XCTAssertEqual(exported["telemetry_version"] as? String, TelemetrySchema.version)
            XCTAssertEqual(exported["time"] as? String, "2026-10-05T12:00:00.123456789Z")
            XCTAssertEqual(exported["mach_time"] as? Int64, SyntheticFlows.machTime)
            XCTAssertEqual(exported["target_path"] as? String, "Not supported")
            XCTAssertEqual(exported["sensor_id"] as? String, "SENSOR")
        }
    }

    /// A new flow's event has its endpoints, names, socket and start time, with the values the flow had.
    func testNewFlowsKeys() throws {
        let flow = try event("new_flow", in: try record(SyntheticFlows.record(.opened)))
        XCTAssertEqual(Set(flow.keys), Self.flowKeys)
        XCTAssertEqual(flow["identifier"] as? String, SyntheticFlows.identifier.uuidString)
        XCTAssertEqual(flow["remote_endpoint"] as? [String: AnyHashable], ["address": "198.35.26.224", "port": 443])
        XCTAssertEqual(flow["remote_address_scope"] as? String, "public")
        XCTAssertEqual(flow["local_endpoint"] as? [String: AnyHashable], ["address": "192.168.64.2", "port": 49_310])
        XCTAssertEqual(flow["remote_hostname"] as? String, "en.wikipedia.org")
        XCTAssertEqual(flow["url"] as? String, "https://en.wikipedia.org/wiki/Endpoint_security")
        XCTAssertEqual(flow["first_party_site"] as? String, "wikipedia.org")
        XCTAssertEqual(flow["direction"] as? String, "outbound")
        XCTAssertEqual(flow["socket_family"] as? Int, 2)
        XCTAssertEqual(flow["socket_type_string"] as? String, "SOCK_STREAM")
        XCTAssertEqual(flow["socket_protocol_string"] as? String, "IPPROTO_TCP")
        XCTAssertEqual(flow["start_time"] as? String, "2026-10-05T12:00:00.119956789Z")
    }

    /// A closed flow adds its byte totals, and leaves them out when its final counts were lost.
    func testClosedFlowsAddTheirBytes() throws {
        let closed = try event("flow_closed", in: try record(SyntheticFlows.record(.closed)))
        XCTAssertEqual(Set(closed.keys), Self.flowKeys.union(["bytes_inbound_count", "bytes_outbound_count"]))
        XCTAssertEqual(closed["bytes_inbound_count"] as? Int, 36_385)
        XCTAssertEqual(closed["bytes_outbound_count"] as? Int, 3_059)
        let lost = try event("flow_closed", in: try record(SyntheticFlows.record(.closed, counted: false)))
        XCTAssertEqual(Set(lost.keys), Self.flowKeys)
    }

    /// What the kernel didn't give is left out: the local end, hostname, URL, first-party site and direction.
    func testAbsentKeysAreLeftOut() throws {
        let minimal = try event("new_flow", in: try record(SyntheticFlows.record(.opened, minimal: true)))
        XCTAssertEqual(Set(minimal.keys), Self.flowKeys.subtracting(["local_endpoint", "remote_hostname", "url",
                                                                     "first_party_site", "direction"]))
    }

    /// A flow's process has a few of a process's keys: all of them while it ran, no session for a zombie, and its
    /// pid alone once it was reaped.
    func testTheProcess() throws {
        let live = try XCTUnwrap(try record(SyntheticFlows.record(.opened))["process"] as? [String: Any])
        XCTAssertEqual(Set(live.keys), Self.processKeys)
        XCTAssertEqual(live["executable"] as? [String: String], ["path": "/usr/bin/nscurl", "name": "nscurl"])
        XCTAssertEqual(Set((live["audit_token"] as? [String: Any] ?? [:]).keys),
                       ["pid", "euid", "ruid", "rgid", "egid", "asid", "auid", "pidversion"])
        XCTAssertEqual(live["codesigning_type"] as? String, "PLATFORM")
        XCTAssertEqual(live["euid_human"] as? String, "root")
        XCTAssertEqual(live["session_id"] as? Int, 512)

        let zombie = SyntheticFlows.record(.opened, process: SyntheticFlows.process(state: .zombie))
        let zombieProcess = try XCTUnwrap(try record(zombie)["process"] as? [String: Any])
        XCTAssertEqual(Set(zombieProcess.keys), Self.processKeys.subtracting(["session_id"]))

        let reaped = SyntheticFlows.record(.opened, process: SyntheticFlows.process(state: .reaped))
        let reapedProcess = try XCTUnwrap(try record(reaped)["process"] as? [String: Any])
        XCTAssertEqual(reapedProcess as? [String: Int], ["pid": 753])
    }

    /// A delegated socket names the app it acts for as `source_app`, in the process's shape.
    func testTheSourceApp() throws {
        let delegate = SyntheticFlows.process(pid: 249, path: "/usr/sbin/mDNSResponder")
        let exported = try record(SyntheticFlows.record(.opened, process: delegate,
                                                        sourceApp: SyntheticFlows.process()))
        let source = try XCTUnwrap(try event("new_flow", in: exported)["source_app"] as? [String: Any])
        XCTAssertEqual(Set(source.keys), Self.processKeys)
        XCTAssertEqual(source["pid"] as? Int, 753)
        XCTAssertEqual((exported["process"] as? [String: Any])?["pid"] as? Int, 249)
    }
}
