//
//  XCTestCase+ScanningSession.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/26/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - A session that scans
extension XCTestCase {
    /// A recording session on fake clients, scanning with a scanner when it's given one.
    ///
    /// - Parameters:
    ///   - factory: The fake clients.
    ///   - scanner: The scanner, or `nil` for a session that doesn't scan.
    ///   - serializer: Builds each event: Mac Monitor's, unless a test gives another.
    ///   - events: The events subscribed to.
    ///   - indicators: The indicators to stamp events with.
    ///   - launchServices: Launch Services, for app execs.
    ///   - emitted: Keeps what the session emits.
    /// - Returns: The session, recording.
    /// - Throws: ``CaptureStartError``.
    func scanningSession(_ factory: FakeEndpointSecurityClientFactory, scanner: FileScanner?,
                         serializer: any EventSerializing = MessageSerializer(),
                         events: [es_event_type_t] = defaultEventSubscriptions,
                         indicators: CompiledIndicators? = nil, launchServices: LaunchServicesReading? = nil,
                         emitted: EmittedEvents) throws -> CaptureSession {
        var configuration = CaptureConfiguration(events: events, label: "Test")
        configuration.indicators = indicators
        configuration.scansWrittenFiles = scanner != nil
        let session = try CaptureSession(configuration, clients: factory, serializer: serializer,
                                         sensorID: { "SENSOR" }, launchServices: launchServices, scanner: scanner,
                                         emit: emitted.append)
        session.isRecording = true
        return session
    }

    /// A close of a real file, with its stat, as Endpoint Security sends it.
    ///
    /// - Parameters:
    ///   - path: The file's path.
    ///   - global: The message's `global_seq_num`.
    ///   - modified: Was the file written?
    /// - Returns: The fixture.
    /// - Throws: The error reading the file's stat.
    func fileClose(of path: String, global: UInt64, modified: Bool = true) throws -> RawMessageFixture {
        let fixture = closeMessage(modified: modified, path: path, global: global)
        fixture.message.pointee.event.close.target.pointee.stat = try fileStat(path)
        return fixture
    }
}
