//
//  StreamRequestTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Stream requests and replies
/// Pins the wire format between `macmonitor` and the Security Extension: version 1's JSON, how either side reads the
/// other's newer messages, and what a Security Extension refuses before it starts a stream.
final class StreamRequestTests: XCTestCase {
    /// Version 1 requests, as `macmonitor` 2.2.0 writes them, read as the values they stand for. A renamed key fails
    /// here.
    ///
    /// - Throws: ``XPCRequestError`` if a request doesn't read.
    func testVersion1RequestsRead() throws {
        XCTAssertEqual(try StreamRequest.decode(Data(#"{"version":1,"kind":"hello"}"#.utf8)), StreamRequest(.hello))
        XCTAssertEqual(try StreamRequest.decode(Data(#"{"version":1,"kind":"stop"}"#.utf8)), StreamRequest(.stop))
        let stream = #"""
            {"version":1,"kind":"stream","options":{"events":["ES_EVENT_TYPE_NOTIFY_EXEC"],"appliesSavedMutes":false}}
            """#
        XCTAssertEqual(try StreamRequest.decode(Data(stream.utf8)),
                       StreamRequest(.stream, options: StreamOptions(events: ["ES_EVENT_TYPE_NOTIFY_EXEC"],
                                                                     appliesSavedMutes: false)))
    }
    
    /// Missing options mean the default events with the saved mutes; unknown fields, such as one a later version adds,
    /// are ignored.
    ///
    /// - Throws: ``XPCRequestError`` if a request doesn't read.
    func testMissingFieldsTakeTheirDefaultsAndUnknownOnesAreIgnored() throws {
        let request = try StreamRequest.decode(Data(#"{"version":1,"kind":"stream","options":{},"later":7}"#.utf8))
        XCTAssertEqual(request.options, StreamOptions())
        XCTAssertEqual(request.options?.appliesSavedMutes, true)
    }
    
    /// Every request survives a round trip.
    ///
    /// - Throws: ``XPCRequestError`` if a request doesn't read.
    func testRequestsRoundTrip() throws {
        for request in [StreamRequest(.hello), StreamRequest(.stop),
                        StreamRequest(.stream, options: StreamOptions(events: ["ES_EVENT_TYPE_NOTIFY_FORK"]))] {
            XCTAssertEqual(try StreamRequest.decode(request.encoded()), request)
        }
    }
    
    /// A newer version, or a kind this build doesn't know, is unsupported rather than malformed. Anything that isn't a
    /// request, a version below 1, or a request too large, is invalid.
    func testWhatIsRefusedAndWhy() {
        let cases: [(String, StreamReply.Status)] = [
            (#"{"version":2,"kind":"stream"}"#, .unsupported),
            (#"{"version":0,"kind":"hello"}"#, .invalid),
            (#"{"version":-7,"kind":"stop"}"#, .invalid),
            (#"{"version":1,"kind":"schema"}"#, .unsupported),
            (#"{"version":1}"#, .invalid),
            (#"{"kind":"stream"}"#, .invalid),
            (#"{"version":"1","kind":"stream"}"#, .invalid),
            (#"[1, 2]"#, .invalid),
            ("not json", .invalid),
            ("", .invalid)
        ]
        for (json, status) in cases {
            XCTAssertThrowsError(try StreamRequest.decode(Data(json.utf8)), json) { error in
                XCTAssertEqual((error as? XPCRequestError)?.status(as: StreamReply.Status.self), status, json)
            }
        }
        let large = Data(repeating: 0x20, count: StreamRequest.maximumSize + 1)
        XCTAssertThrowsError(try StreamRequest.decode(large)) { error in
            XCTAssertEqual((error as? XPCRequestError)?.status(as: StreamReply.Status.self), .invalid)
        }
    }
    
    /// A version 1 reply reads; a reply with a status this build doesn't know reads as unsupported; a reply without
    /// its version, status or Security Extension version doesn't read.
    func testRepliesRead() {
        let started = #"""
            {"version":1,"status":"ok","sensorVersion":"2.2.0 (1)",\#
            "stream":{"events":["ES_EVENT_TYPE_NOTIFY_EXEC"],"savedMutes":3}}
            """#
        XCTAssertEqual(StreamReply.decode(Data(started.utf8)),
                       StreamReply(.ok, sensorVersion: "2.2.0 (1)",
                                   stream: StreamStarted(events: ["ES_EVENT_TYPE_NOTIFY_EXEC"], savedMutes: 3)))
        let stopped = #"""
            {"version":1,"status":"ok","sensorVersion":"2.2.0 (1)","summary":{"captured":9,"delivered":8,\#
            "droppedByEndpointSecurity":1,"droppedWhileBehind":2,"skippedWhilePaused":5,"pauses":1}}
            """#
        XCTAssertEqual(StreamReply.decode(Data(stopped.utf8))?.summary,
                       StreamSummary(captured: 9, delivered: 8, droppedByEndpointSecurity: 1, droppedWhileBehind: 2,
                                     skippedWhilePaused: 5, pauses: 1))
        XCTAssertEqual(StreamReply.decode(Data(#"{"version":3,"status":"later","sensorVersion":"3.0 (1)"}"#.utf8))?
                        .status, .unsupported)
        XCTAssertNil(StreamReply.decode(Data(#"{"version":1,"status":"ok"}"#.utf8)))
        let reply = StreamReply(.sessionLimit, problem: "Three streams are running.", sensorVersion: "2.2.0 (1)")
        XCTAssertEqual(StreamReply.decode(reply.encoded()), reply)
    }
}

