//
//  FlowLaneTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - The network lane
/// Pins a capture session's network lane on records handed to it as the client's delivery queue hands them: what it
/// admits and in which order, its own sockets, mutes, URL paths, indicators, snapshots from the lineage table, and
/// closing.
final class FlowLaneTests: XCTestCase {
    let emitted = EmittedEvents()

    /// A lane that records both flow events.
    ///
    /// - Parameters:
    ///   - client: Its client, which it isn't registered with: one of its own unless given.
    ///   - mutes: Its mutes.
    ///   - mutesSelf: Leave out the Security Extension's own sockets?
    ///   - lineage: The lineage table, for snapshots.
    /// - Returns: The lane, recording.
    private func makeLane(client: NetworkStatisticsClient = .fake(), mutes: MuteList = MuteList(),
                          mutesSelf: Bool = true, lineage: ProcessLineage? = nil) -> FlowLane {
        let lane = FlowLane(client: client, sensorID: "SENSOR", indicators: nil, chains: nil, mutes: FlowMutes(mutes),
                            mutesSelf: mutesSelf, recordsURLPaths: true, lineage: lineage,
                            snapshots: SnapshotLedger(), macOS: "27.2 (Build 26B123)", sipStatus: .disabled,
                            bootSession: nil, emit: emitted.append)
        lane.setSubscribed(Set(MacMonitorEvent.allCases))
        lane.setRecording(true)
        return lane
    }

    /// The events emitted, as `Message`s, without the snapshots.
    ///
    /// - Returns: The events, in order.
    /// - Throws: If one doesn't decode.
    private func events() throws -> [Message] {
        try emitted.all.filter { !ProcessSnapshotRecord.isSnapshot($0.json) }.map {
            try JSONDecoder().decode(Message.self, from: $0.json)
        }
    }

    /// A record's own socket, as the client marks the Security Extension's.
    ///
    /// - Parameter kind: Opened or closed.
    /// - Returns: The record.
    private func own(_ kind: FlowRecord.Kind) -> FlowRecord {
        let record = SyntheticFlows.record(kind)
        return FlowRecord(kind: kind, identifier: record.identifier, process: record.process, sourceApp: nil,
                          isOwn: true, local: record.local, remote: record.remote, family: record.family,
                          type: record.type, proto: record.proto, hostname: record.hostname, url: record.url,
                          firstPartySite: record.firstPartySite, direction: record.direction, start: record.start,
                          time: record.time, bytesIn: record.bytesIn, bytesOut: record.bytesOut)
    }

    /// A subscribed flow becomes its event on the network lane. An unsubscribed one is left out without being
    /// skipped, and one handed over while not recording is skipped. Every record is counted.
    func testAdmission() throws {
        let lane = makeLane()
        lane.handle(SyntheticFlows.record(.opened))
        let opened = try XCTUnwrap(try events().first)
        XCTAssertEqual(opened.es_event_type, "new_flow")
        XCTAssertEqual(opened.event_type, 1_001)
        XCTAssertEqual(opened.sensor_id, "SENSOR")
        XCTAssertEqual(emitted.all.map(\.eventClass), [.network])
        lane.setSubscribed([.new_flow])
        lane.handle(SyntheticFlows.record(.closed))
        lane.setRecording(false)
        lane.handle(SyntheticFlows.record(.opened))
        lane.handle(SyntheticFlows.record(.closed))
        XCTAssertEqual(try events().count, 1)
        XCTAssertEqual(lane.skippedMessages, 1, "Only the subscribed opening is skipped")
        let statistics = lane.statistics()
        XCTAssertEqual(statistics.records, 4)
        XCTAssertEqual(statistics.skipped, 1)
    }

    /// The Security Extension's own sockets are left out when the session mutes itself, and kept when it doesn't.
    func testItsOwnSockets() throws {
        makeLane().handle(own(.opened))
        XCTAssertTrue(emitted.all.isEmpty)
        makeLane(mutesSelf: false).handle(own(.opened))
        XCTAssertEqual(try events().count, 1)
    }

    /// A process mute for every event mutes both flow events, one for `new_flow` only its openings, and a target
    /// mute never applies. A muted record is counted, never skipped.
    func testMutes() throws {
        let every = MuteList([PathMute(path: "/usr/bin/nscurl", type: ES_MUTE_PATH_TYPE_LITERAL)])
        let lane = makeLane(mutes: every)
        lane.handle(SyntheticFlows.record(.opened))
        lane.handle(SyntheticFlows.record(.closed))
        XCTAssertTrue(emitted.all.isEmpty)
        XCTAssertEqual(lane.statistics().muted, 2)
        XCTAssertEqual(lane.skippedMessages, 0)
        lane.setMutes(FlowMutes(MuteList([PathMute(path: "/usr/bin/", type: ES_MUTE_PATH_TYPE_PREFIX,
                                                   events: [MacMonitorEvent.new_flow.type]),
                                          PathMute(path: "/usr/bin/nscurl", type: ES_MUTE_PATH_TYPE_TARGET_LITERAL)])))
        lane.handle(SyntheticFlows.record(.opened))
        lane.handle(SyntheticFlows.record(.closed))
        XCTAssertEqual(try events().map(\.es_event_type), ["flow_closed"])
    }

    /// With URL paths off, a flow's URL ends at its host. Turning them on again keeps the path from the next record.
    func testURLPaths() throws {
        let lane = makeLane()
        lane.setRecordsURLPaths(false)
        lane.handle(SyntheticFlows.record(.opened))
        lane.setRecordsURLPaths(true)
        lane.handle(SyntheticFlows.record(.closed))
        XCTAssertEqual(try events().map { $0.event.networkFlow?.url },
                       ["https://en.wikipedia.org", "https://en.wikipedia.org/wiki/Endpoint_security"])
    }

    /// Each event is stamped with the indicators it matches, from the set the lane was last given.
    func testIndicatorsAreStamped() throws {
        let lane = makeLane()
        let rule = #"event.new_flow != nil AND event.new_flow.remote_hostname ENDSWITH "wikipedia.org""#
        let indicator = Indicator(name: "Wikipedia", description: "", symbol: "star", color: .blue, predicate: rule)
        lane.setIndicators(CompiledIndicators([indicator]), chains: nil)
        lane.handle(SyntheticFlows.record(.opened))
        lane.handle(SyntheticFlows.record(.closed))
        let events = try events()
        XCTAssertEqual(events.first?.indicators?.hits.map(\.name), ["Wikipedia"])
        XCTAssertEqual(events.last?.indicators?.hits.map(\.name), [])
        XCTAssertEqual(events.first?.indicators?.hits.first?.evaluated_by, .securityExtension)
    }

    /// A flow's process is described only from a program the lineage table knows, ahead of its event. One the table
    /// doesn't know yet is tried again on the process's next record, and once described it isn't again.
    func testSnapshotsComeFromTheLineageTable() throws {
        let lineage = ProcessLineage()
        let lane = makeLane(lineage: lineage)
        lane.handle(SyntheticFlows.record(.opened))
        XCTAssertFalse(emitted.all.contains { ProcessSnapshotRecord.isSnapshot($0.json) })
        let key = ProcessKey(pid: 753, pidversion: 2_341)
        lineage.exec(ProcessProgram(key: key, path: "/usr/bin/nscurl", signingID: "com.apple.nscurl"),
                     replacing: key, at: 0)
        lane.handle(SyntheticFlows.record(.closed))
        lane.handle(SyntheticFlows.record(.opened))
        let lines = emitted.all.map { ProcessSnapshotRecord.isSnapshot($0.json) }
        XCTAssertEqual(lines, [false, true, false, false], "One snapshot, ahead of the second record")
        let snapshot = try XCTUnwrap(ProcessSnapshotRecord.read(emitted.all[1].json))
        XCTAssertEqual(snapshot.process_snapshot.executable?.path, "/usr/bin/nscurl")
        XCTAssertEqual(snapshot.process_snapshot.key, key.description)
    }

    /// A closed lane takes no more records. Waiting for it returns once nothing is being built.
    func testClosing() {
        let lane = makeLane()
        lane.close()
        lane.handle(SyntheticFlows.record(.opened))
        XCTAssertTrue(emitted.all.isEmpty)
        XCTAssertEqual(lane.skippedMessages, 0, "A closed lane's records aren't skipped")
        XCTAssertTrue(lane.waitUntilIdle(until: .now() + 1))
    }

    /// A record still being built when waiting gives up is dropped, and never emitted after. Here its process's
    /// parent is being read from the system.
    func testARecordBuiltPastTheDeadlineIsDropped() {
        let reading = DispatchSemaphore(value: 0), held = DispatchSemaphore(value: 0)
        let lineage = ProcessLineage(reader: { _ in
            reading.signal()
            held.wait()
            return nil
        }, patience: 0, waitBudget: 0)
        let key = ProcessKey(pid: 753, pidversion: 2_341)
        lineage.exec(ProcessProgram(key: key, path: "/usr/bin/nscurl", signingID: "com.apple.nscurl"),
                     replacing: key, parent: ProcessKey(pid: 600, pidversion: 1), at: 0)
        let lane = makeLane(lineage: lineage), handled = DispatchGroup()
        DispatchQueue.global().async(group: handled) { lane.handle(SyntheticFlows.record(.opened)) }
        XCTAssertEqual(reading.wait(timeout: .now() + 5), .success, "The record waits on its parent")
        lane.close()
        XCTAssertFalse(lane.waitUntilIdle(until: .now() + .milliseconds(50)))
        held.signal()
        XCTAssertEqual(handled.wait(timeout: .now() + 5), .success)
        XCTAssertTrue(emitted.all.isEmpty)
    }

    /// A lane reads the client's counts together with its registration. When one lane leaves as another joins,
    /// each counts the sockets lost while it was registered, whichever goes first.
    func testALaneJoiningAsAnotherLeavesCountsItsOwnLosses() {
        let flows = FlowClientHarness()
        let leaving = makeLane(client: flows.client), joining = makeLane(client: flows.client)
        XCTAssertTrue(leaving.register())
        XCTAssertTrue(flows.feed(flows.flow(lost: 50)))
        let held = DispatchSemaphore(value: 0), done = DispatchGroup()
        flows.client.readQueue.async { held.wait() }
        DispatchQueue.global().async(group: done) { leaving.unregister() }
        DispatchQueue.global().async(group: done) { _ = joining.register() }
        let changed = waitUntil(timeout: 2) {
            flows.client.consumers.withLockUnchecked { $0.count == 1 && $0.first === joining }
        }
        XCTAssertTrue(changed, "Both changed the consumers before either read the client")
        held.signal()
        XCTAssertEqual(done.wait(timeout: .now() + 5), .success)
        XCTAssertTrue(flows.feed(flows.flow(lost: 3)))
        XCTAssertEqual(leaving.statistics().socketsLost, 50)
        XCTAssertEqual(joining.statistics().socketsLost, 3)
    }
}
