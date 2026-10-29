//
//  MutedPathTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/29/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Muted paths Endpoint Security reports
/// Pins how a mute Endpoint Security reports, such as one of Apple's default mutes, is named for Export Apple Mute
/// Set…: every event type the SDK defines by its `ESTypes.h` name, never `ES_EVENT_TYPE_LAST`.
final class MutedPathTests: XCTestCase {
    /// A reported mute with every event type the SDK defines names each one, in order.
    func testEveryEventOfAReportedMuteIsNamed() {
        let events = (0..<ES_EVENT_TYPE_LAST.rawValue).map { es_event_type_t(rawValue: $0) }
        let path = "/usr/libexec/diagnosticd"
        let muted = events.withUnsafeBufferPointer { buffer in
            path.withCString { cPath in
                ESMutedPath(fromRawESPath: es_muted_path_t(
                    type: ES_MUTE_PATH_TYPE_LITERAL, event_count: buffer.count, events: buffer.baseAddress,
                    path: es_string_token_t(length: strlen(cPath), data: cPath)))
            }
        }
        XCTAssertEqual(muted.path, path)
        XCTAssertEqual(muted.type, "ES_MUTE_PATH_TYPE_LITERAL")
        XCTAssertEqual(muted.eventCount, events.count)
        XCTAssertEqual(muted.events, events.map { eventTypeToString(from: $0) })
        XCTAssertFalse(muted.events.contains("ES_EVENT_TYPE_LAST"))
        XCTAssertTrue(muted.events.contains("ES_EVENT_TYPE_AUTH_BOOTSTRAP_LOOK_UP"))
    }
}
