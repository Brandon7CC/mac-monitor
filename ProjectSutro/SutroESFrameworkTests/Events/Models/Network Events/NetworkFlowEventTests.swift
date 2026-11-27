//
//  NetworkFlowEventTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Network flows as messages
/// Pins how a flow the client hands over becomes a `Message`: its times, its names, its URL with or without its path,
/// its context, and its process, which the record writes the same from the message and from the stored row.
final class NetworkFlowEventTests: XCTestCase {
    /// The flow's time is the record's `time`, `mach_time` and `message_darwin_time` alike, and the socket's creation
    /// is `start_time` on both events.
    func testTimesAgree() throws {
        for kind in [FlowRecord.Kind.opened, .closed] {
            let message = SyntheticFlows.message(SyntheticFlows.record(kind))
            XCTAssertEqual(message.time, "2026-10-05T12:00:00.123456789Z")
            XCTAssertEqual(message.mach_time, SyntheticFlows.machTime)
            let parsed = try XCTUnwrap(ESLogger.date(fromTime: message.time, legacy: false))
            XCTAssertEqual(message.message_darwin_time.timeIntervalSince1970, parsed.timeIntervalSince1970,
                           accuracy: 1e-6)
            XCTAssertEqual(message.event.networkFlow?.start_time, "2026-10-05T12:00:00.119956789Z")
        }
        XCTAssertEqual(ESLogger.time(nanoseconds: 1_500_000_000), "1970-01-01T00:00:01.500000000Z")
    }

    /// A flow's message names its event from its payload, and has no version, sequence numbers, thread or action.
    func testNamesAndEnvelope() {
        for (kind, event) in [(FlowRecord.Kind.opened, MacMonitorEvent.new_flow), (.closed, .flow_closed)] {
            let message = SyntheticFlows.message(SyntheticFlows.record(kind))
            XCTAssertEqual(message.event.macMonitorEvent, event)
            XCTAssertEqual(message.event_type, Int(event.rawValue))
            XCTAssertEqual(message.es_event_type, event.name)
            XCTAssertEqual([message.version, message.schema_version], [0, 0])
            XCTAssertNil(message.seq_num)
            XCTAssertNil(message.global_seq_num)
            XCTAssertNil(message.thread)
            XCTAssertNil(message.action.result)
            XCTAssertEqual(message.action_type_string, "ES_ACTION_TYPE_NOTIFY")
            XCTAssertNil(message.target_path)
            XCTAssertEqual(message.sensor_id, "SENSOR")
            let flow = message.event.networkFlow
            XCTAssertEqual([flow?.socket_family_string, flow?.socket_type_string, flow?.socket_protocol_string],
                           ["AF_INET", "SOCK_STREAM", "IPPROTO_TCP"])
            XCTAssertEqual(flow?.identifier, SyntheticFlows.identifier)
        }
        let opened = SyntheticFlows.message(SyntheticFlows.record(.opened)).event.networkFlow
        XCTAssertNil(opened?.bytes_inbound_count, "A new flow has no counts")
        let closed = SyntheticFlows.message(SyntheticFlows.record(.closed)).event.networkFlow
        XCTAssertEqual([closed?.bytes_inbound_count, closed?.bytes_outbound_count], [36_385, 3_059])
    }

    /// The URL keeps its path while URL paths are recorded, and ends at the host and port otherwise.
    func testURLPathKeptOrCut() {
        let record = SyntheticFlows.record(.opened, url: "https://en.wikipedia.org:8443/wiki/Endpoint_security")
        XCTAssertEqual(SyntheticFlows.message(record).event.networkFlow?.url,
                       "https://en.wikipedia.org:8443/wiki/Endpoint_security")
        XCTAssertEqual(SyntheticFlows.message(record, keepingURLPath: false).event.networkFlow?.url,
                       "https://en.wikipedia.org:8443")
        XCTAssertNil(SyntheticFlows.message(SyntheticFlows.record(.opened, minimal: true), keepingURLPath: false)
            .event.networkFlow?.url)
    }

    /// The context is the URL, else the host and port, and a closed flow adds its bytes in.
    func testContext() {
        func context(_ record: FlowRecord) -> String? { SyntheticFlows.message(record).context }
        XCTAssertEqual(context(SyntheticFlows.record(.opened)), "https://en.wikipedia.org/wiki/Endpoint_security")
        XCTAssertEqual(context(SyntheticFlows.record(.opened, minimal: true)), "198.35.26.224:443")
        XCTAssertEqual(context(SyntheticFlows.record(.closed, minimal: true)), "198.35.26.224:443 · 36.4 KB in")
        XCTAssertEqual(context(SyntheticFlows.record(.closed, minimal: true, counted: false)), "198.35.26.224:443")
        var flow = SyntheticFlows.message(SyntheticFlows.record(.opened, minimal: true)).event.networkFlow!
        flow.remote_endpoint = FlowEndpoint(address: "2001:db8::1", port: 443)
        XCTAssertEqual(flow.summary(closed: false), "[2001:db8::1]:443")
        flow.remote_hostname = "2001:db8::2"
        XCTAssertEqual(flow.summary(closed: false), "[2001:db8::2]:443", "A hostname that's an IPv6 literal")
        flow.remote_hostname = "en.wikipedia.org"
        XCTAssertEqual(flow.summary(closed: false), "en.wikipedia.org:443")
        let counts: [(Int64, String)] = [(0, "0 bytes"), (1, "1 byte"), (999, "999 bytes"), (1_000, "1.0 KB"),
                                         (36_385, "36.4 KB"), (999_960, "1.0 MB"), (1_234_567_890, "1.2 GB")]
        for (bytes, text) in counts { XCTAssertEqual(NetworkFlowEvent.byteCount(bytes), text, "\(bytes)") }
    }

    /// A flow's process carries its parent, group and session when they were read, and an unread one is
    /// `Process.unread`. Its users are named, a real user unlike the effective one too, and its signing values kept.
    /// Nothing else is made up.
    func testProcessFromFlow() throws {
        let live = Process(flow: SyntheticFlows.process())
        XCTAssertEqual([live.pid, live.ppid, live.group_id, live.session_id], [753, 512, 753, 512])
        XCTAssertEqual(live.audit_token?.pidversion, 2_341)
        XCTAssertEqual(live.audit_token_string, try XCTUnwrap(live.audit_token).toString())
        XCTAssertEqual(live.euid, 0)
        XCTAssertEqual([live.euid_human, live.ruid_human], ["root", "root"])
        XCTAssertEqual(live.executable?.path, "/usr/bin/nscurl")
        XCTAssertEqual(live.signing_id, "com.apple.nscurl")
        XCTAssertEqual(live.codesigning_type, .platform)
        XCTAssertEqual(live.codesigning_flags, 0)
        XCTAssertFalse(live.is_platform_binary)
        XCTAssertNil(live.cdhash)

        var setuid = SyntheticFlows.process()
        setuid.token?.val.3 = 1
        let named = Process(flow: setuid)
        XCTAssertEqual([named.euid, named.ruid], [0, 1])
        XCTAssertEqual([named.euid_human, named.ruid_human], ["root", "daemon"], "A real user unlike the effective")

        let zombie = Process(flow: SyntheticFlows.process(state: .zombie))
        XCTAssertEqual([zombie.ppid, zombie.group_id, zombie.session_id], [512, 753, Process.unread])

        let reaped = Process(flow: SyntheticFlows.process(state: .reaped))
        XCTAssertEqual([reaped.pid, reaped.ppid, reaped.group_id, reaped.session_id],
                       [753, Process.unread, Process.unread, Process.unread])
        XCTAssertNil(reaped.audit_token)
        XCTAssertNil(reaped.executable)
        XCTAssertNil(reaped.euid)
        XCTAssertEqual(reaped.codesigning_type, .unknown)
        XCTAssertEqual(FlowProcessRecord(reaped), FlowProcessRecord(pid: 753, token: nil, euidHuman: nil, ppid: nil,
                                                                    groupID: nil, sessionID: nil, path: nil,
                                                                    signingID: nil, teamID: nil,
                                                                    codesigningType: nil))
    }

    /// The record writes a flow's process the same from its `Process` as from the row the event store keeps of it,
    /// and reads it back as the same `Process`.
    func testProcessRecordFromMessageAndRowAgree() throws {
        let messages = SyntheticCorpus.networkRecords().map(\.message)
        XCTAssertGreaterThan(messages.count, 10)
        for message in messages {
            let fromMessage = FlowProcessRecord(message.process)
            let fromRow = withStoredEvent(message) { FlowProcessRecord($0.process) }
            XCTAssertEqual(fromMessage, fromRow, message.context ?? "")
            XCTAssertEqual(FlowProcessRecord(Process(fromMessage)), fromMessage)
        }
    }

    /// A delegated flow that closed with its counts has every key a flow can have, its source app's too.
    func testAFullFlowFillsEveryKey() throws {
        let delegate = SyntheticFlows.process(pid: 249, path: "/usr/sbin/mDNSResponder")
        let record = SyntheticFlows.record(.closed, process: delegate, sourceApp: SyntheticFlows.process())
        let flow = try XCTUnwrap(SyntheticFlows.message(record).event.networkFlow)
        XCTAssertEqual(SyntheticCorpus.gaps(in: flow, absent: []), [])
        XCTAssertEqual(flow.source_app?.executable?.name, "nscurl")
    }
}
