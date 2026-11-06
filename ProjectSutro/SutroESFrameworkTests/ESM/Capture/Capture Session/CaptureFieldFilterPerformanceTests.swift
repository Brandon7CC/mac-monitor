//
//  CaptureFieldFilterPerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - What leaving out a close saves
/// Measures a file lane handed unmodified closes with the real ``MessageSerializer``: with the modified-only filter
/// each is counted and left out, without it each is built and encoded. Compare the two tests' times.
final class CaptureFieldFilterPerformanceTests: XCTestCase {
    /// How many closes each measured run hands the lane.
    private static let closes = 20_000

    /// Time handing ``closes`` unmodified closes to a recording file lane.
    ///
    /// - Parameter filters: The session's field filters.
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    private func measureCloses(filters: Set<FieldFilter>) throws {
        let factory = FakeEndpointSecurityClientFactory()
        var configuration = CaptureConfiguration(events: [ES_EVENT_TYPE_NOTIFY_CLOSE], label: "Test")
        configuration.fieldFilters = filters
        let session = try CaptureSession(configuration, clients: factory, serializer: MessageSerializer(),
                                         sensorID: { "SENSOR" }, emit: { _ in })
        session.isRecording = true
        let close = closeMessage(modified: false, path: "/Users/test/Library/Preferences/com.example.plist", global: 1)
        let client = factory.client(.file)
        measure {
            for _ in 0..<Self.closes { client.deliver(close) }
        }
        let file = try XCTUnwrap(session.statistics().first { $0.eventClass == .file })
        XCTAssertEqual(file.serializationFailures, 0)
        XCTAssertEqual(file.fieldFiltered, filters.isEmpty ? 0 : file.messages)
    }

    /// Unmodified closes left out: counted under the control lock, never serialized.
    func testUnmodifiedClosesLeftOut() throws {
        try measureCloses(filters: [.modifiedCloses])
    }

    /// The same closes without the filter: each one is built and encoded.
    func testUnmodifiedClosesSerialized() throws {
        try measureCloses(filters: [])
    }
}
