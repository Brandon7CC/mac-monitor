//
//  StreamStatusTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/9/26.
//

import XCTest
import os
@testable import SutroESFramework


// MARK: - Status requests
/// Pins what the Security Extension answers a status request, which `macmonitor status` sends: anyone `macmonitor`
/// runs as may ask, it says who is capturing, and it only asks Endpoint Security for a client when nothing there
/// holds one to judge by.
final class StreamStatusTests: XCTestCase {
    private var savedMutes = SavedMuteSet(testing: MuteStore(directory: URL(fileURLWithPath: "/nonexistent")))

    override func setUpWithError() throws {
        try super.setUpWithError()
        savedMutes = SavedMuteSet(testing: try makeMuteStore())
    }

    /// A caller who may not stream may still ask for the status, and is still refused a stream.
    func testAnyCallerMayAsk() {
        let harness = StreamHarness(savedMutes: savedMutes, admits: false)
        let connection = harness.connect(reader: TestStreamReader())
        defer { connection.invalidate() }
        let reply = connection.send(StreamRequest(.status).encoded())
        XCTAssertEqual(reply?.status, .ok)
        XCTAssertEqual(reply?.sensorVersion, "3.0.0 (1)")
        XCTAssertEqual(reply?.report, SensorReport(endpointSecurity: .ok,
                                                   app: SensorReport.App(connected: false, recording: false),
                                                   streams: 0, streamCapacity: SensorXPC.maxCommandLineStreams))
        XCTAssertEqual(connection.send(StreamRequest(.stream, options: StreamOptions()).encoded())?.status, .refused)
        XCTAssertEqual(connection.send(StreamRequest(.hello).encoded())?.status, .refused)
    }

    /// An idle Security Extension asks Endpoint Security for a client, and says what it answered: without Full Disk
    /// Access, that it isn't permitted.
    func testAnIdleSecurityExtensionAsksEndpointSecurity() {
        let asked = OSAllocatedUnfairLock(initialState: 0)
        let harness = StreamHarness(savedMutes: savedMutes, probe: {
            asked.withLock { $0 += 1 }
            return .notPermitted
        })
        let connection = harness.connect(reader: TestStreamReader())
        defer { connection.invalidate() }
        XCTAssertEqual(connection.send(StreamRequest(.status).encoded())?.report?.endpointSecurity, .notPermitted)
        XCTAssertEqual(asked.withLock { $0 }, 1)
    }

    /// While a stream holds Endpoint Security clients, the report counts it and says Endpoint Security allows
    /// clients, without asking for another.
    func testARunningStreamIsCountedAndNotProbed() {
        let asked = OSAllocatedUnfairLock(initialState: 0)
        let harness = StreamHarness(savedMutes: savedMutes, capacity: 2, probe: {
            asked.withLock { $0 += 1 }
            return .notPermitted
        })
        let streaming = harness.connect(reader: TestStreamReader())
        defer { streaming.invalidate() }
        XCTAssertEqual(streaming.send(StreamRequest(.stream, options: StreamOptions()).encoded())?.status, .ok)
        let asking = harness.connect(reader: TestStreamReader())
        defer { asking.invalidate() }
        let report = asking.send(StreamRequest(.status).encoded())?.report
        XCTAssertEqual(report?.streams, 1)
        XCTAssertEqual(report?.streamCapacity, 2)
        XCTAssertEqual(report?.endpointSecurity, .ok)
        XCTAssertEqual(asked.withLock { $0 }, 0)
    }

    /// Mac Monitor's side says whether the app is connected and recording, and its capture holding clients spares
    /// the probe too.
    func testTheAppsCaptureIsReported() {
        let harness = StreamHarness(savedMutes: savedMutes, appCapture: {
            $0(SensorReport.App(connected: true, recording: true), true)
        }, probe: { .tooManyClients })
        let connection = harness.connect(reader: TestStreamReader())
        defer { connection.invalidate() }
        let report = connection.send(StreamRequest(.status).encoded())?.report
        XCTAssertEqual(report?.app, SensorReport.App(connected: true, recording: true))
        XCTAssertEqual(report?.endpointSecurity, .ok)
    }

    /// The report says which indicator pack Mac Monitor's own indicators are: the build's, then a pack once one is
    /// installed. A Security Extension that keeps no indicators says nothing of them.
    func testTheIndicatorPackIsReported() throws {
        let indicators = try makeSavedIndicatorSet(defaults: try linkedFixtures(), verifier: try packVerifier())
        let harness = StreamHarness(savedMutes: savedMutes, admits: false, savedIndicators: indicators)
        let connection = harness.connect(reader: TestStreamReader())
        defer { connection.invalidate() }
        XCTAssertEqual(connection.send(StreamRequest(.status).encoded())?.report?.indicators,
                       IndicatorPackStatus(sequence: 0, source: .linked, mode: .notify))
        XCTAssertEqual(indicators.send(IndicatorRequest(.installPack, pack: try releaseFixture(2).file)).status, .ok)
        let installed = connection.send(StreamRequest(.status).encoded())?.report?.indicators
        XCTAssertEqual(installed?.sequence, 2)
        XCTAssertEqual(installed?.source, .installed)

        let without = StreamHarness(savedMutes: savedMutes)
        let none = without.connect(reader: TestStreamReader())
        defer { none.invalidate() }
        let report = try XCTUnwrap(none.send(StreamRequest(.status).encoded())?.report)
        XCTAssertNil(report.indicators)
    }

    /// An update check has the Security Extension's updater look up the latest release, and replies with what it
    /// found. Anyone `macmonitor` runs as may ask. A build that doesn't update itself answers nothing, and a service
    /// with no updater says it can't.
    func testAnUpdateCheckAsksTheUpdater() {
        let release = UpdateDetails(version: "v9.0.0", downloadURL: URL(string: "https://example.com/a.pkg")!,
                                    releaseNotes: "Notes.", releaseDate: "2026-11-21T10:00:00Z")
        let answers: [UpdateCheck?] = [.newer(release), .upToDate, .failed, nil]
        for answer in answers {
            let updater = FakeUpdater(answering: answer)
            let harness = StreamHarness(savedMutes: savedMutes, admits: false, updates: updater)
            let connection = harness.connect(reader: TestStreamReader())
            defer { connection.invalidate() }
            let reply = connection.send(StreamRequest(.updateCheck).encoded())
            XCTAssertEqual(reply?.status, .ok)
            XCTAssertEqual(reply?.update, answer)
            XCTAssertEqual(updater.asked.checks, 1)
            XCTAssertEqual(updater.asked.installs, 0)
        }
        let without = StreamHarness(savedMutes: savedMutes)
        let connection = without.connect(reader: TestStreamReader())
        defer { connection.invalidate() }
        let reply = connection.send(StreamRequest(.updateCheck).encoded())
        XCTAssertEqual(reply?.status, .failed)
        XCTAssertEqual(reply?.problem, "This Security Extension doesn't look up releases.")
    }

    /// A report reads back as it was written, an Endpoint Security answer this build doesn't know reads as failed,
    /// what a newer Security Extension says of its indicators that this build can't read is left out, and every
    /// `es_new_client` result has a name.
    func testTheReportsWireShape() throws {
        let report = SensorReport(endpointSecurity: .notPermitted, app: SensorReport.App(connected: true,
                                                                                         recording: false),
                                  streams: 2, streamCapacity: 3,
                                  indicators: IndicatorPackStatus(sequence: 4, source: .installed, commit: "abc"))
        let data = try JSONEncoder().encode(report)
        XCTAssertEqual(try JSONDecoder().decode(SensorReport.self, from: data), report)
        let later = Data(#"{"endpointSecurity":"ok","app":{"connected":false,"recording":false},"streams":0,"#.utf8)
            + Data(#""streamCapacity":3,"indicators":{"sequence":4,"source":"mirrored"}}"#.utf8)
        let read = try JSONDecoder().decode(SensorReport.self, from: later)
        XCTAssertNil(read.indicators)
        XCTAssertEqual(read.streamCapacity, 3)
        let newer = Data(#"{"endpointSecurity":"later","app":{"connected":false,"recording":false},"#.utf8)
            + Data(#""streams":0,"streamCapacity":3}"#.utf8)
        XCTAssertEqual(try JSONDecoder().decode(SensorReport.self, from: newer).endpointSecurity, .failed)
        XCTAssertEqual(SensorReport.EndpointSecurity(.success), .ok)
        XCTAssertEqual(SensorReport.EndpointSecurity(.notPermitted), .notPermitted)
        XCTAssertEqual(SensorReport.EndpointSecurity(.notEntitled), .notEntitled)
        XCTAssertEqual(SensorReport.EndpointSecurity(.tooManyClients), .tooManyClients)
        XCTAssertEqual(SensorReport.EndpointSecurity(.internalSubsystem), .failed)
    }
}
