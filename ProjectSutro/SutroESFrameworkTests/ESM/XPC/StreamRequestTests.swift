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
    /// Version 1 requests, as `macmonitor` 3.0.0 writes them, read as the values they stand for. A renamed key fails
    /// here.
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
    
    /// Missing options mean the default events with the saved mutes. Unknown fields, such as one a later version adds,
    /// are ignored.
    func testMissingFieldsTakeTheirDefaultsAndUnknownOnesAreIgnored() throws {
        let request = try StreamRequest.decode(Data(#"{"version":1,"kind":"stream","options":{},"later":7}"#.utf8))
        XCTAssertEqual(request.options, StreamOptions())
        XCTAssertEqual(request.options?.appliesSavedMutes, true)
        XCTAssertNil(request.options?.fieldFilters, "A 3.0.0 request")
    }
    
    /// Field filters round-trip, including none at all, which is not the same as a 3.0.0 request that names none.
    /// Without them, the key isn't written, so a 3.0.0 Security Extension reads the request as before.
    func testFieldFiltersRoundTrip() throws {
        let json = #"""
            {"version":1,"kind":"stream","options":{"fieldFilters":["ES_EVENT_TYPE_NOTIFY_CLOSE.modified"]}}
            """#
        let request = try StreamRequest.decode(Data(json.utf8))
        XCTAssertEqual(request.options?.fieldFilters, ["ES_EVENT_TYPE_NOTIFY_CLOSE.modified"])
        XCTAssertEqual(try StreamRequest.decode(request.encoded()), request)
        let none = StreamRequest(.stream, options: StreamOptions(fieldFilters: []))
        XCTAssertEqual(try StreamRequest.decode(none.encoded()).options?.fieldFilters, [])
        let legacy = String(decoding: StreamRequest(.stream, options: StreamOptions()).encoded(), as: UTF8.self)
        XCTAssertFalse(legacy.contains("fieldFilters"), legacy)
    }
    
    /// Every request survives a round trip.
    func testRequestsRoundTrip() throws {
        for request in [StreamRequest(.hello), StreamRequest(.stop),
                        StreamRequest(.stream, options: StreamOptions(events: ["ES_EVENT_TYPE_NOTIFY_FORK"]))] {
            XCTAssertEqual(try StreamRequest.decode(request.encoded()), request)
        }
    }
    
    /// A newer version, or a kind this build doesn't know, is unsupported rather than malformed. Anything that isn't a
    /// request, or a version below 1, is invalid.
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
            let error = thrown(XPCRequestError.self) { try StreamRequest.decode(Data(json.utf8)) }
            XCTAssertEqual(error?.status(as: StreamReply.Status.self), status, json)
        }
    }
    
    /// A request of every kind, padded with spaces to exactly 64 KiB, reads. One byte more is too large, though it's
    /// still the same request.
    func testTheSizeLimitIsExact() {
        let options = StreamOptions(events: ["ES_EVENT_TYPE_NOTIFY_EXEC"],
                                    fieldFilters: ["ES_EVENT_TYPE_NOTIFY_CLOSE.modified"])
        assertSizeLimit(StreamRequest.Kind.allCases.map { StreamRequest($0, options: options) },
                        refusal: "The request is larger than 64 KiB.")
    }
    
    /// A version 1 reply reads. A reply with a status this build doesn't know reads as unsupported. A reply without
    /// its version, status or Security Extension version doesn't read.
    func testRepliesRead() {
        let started = #"""
            {"version":1,"status":"ok","sensorVersion":"3.0.0 (1)",\#
            "stream":{"events":["ES_EVENT_TYPE_NOTIFY_EXEC"],"savedMutes":3}}
            """#
        XCTAssertEqual(StreamReply.decode(Data(started.utf8)),
                       StreamReply(status: .ok, sensorVersion: "3.0.0 (1)",
                                   stream: StreamStarted(events: ["ES_EVENT_TYPE_NOTIFY_EXEC"], savedMutes: 3)))
        let stopped = #"""
            {"version":1,"status":"ok","sensorVersion":"3.0.0 (1)","summary":{"captured":9,"delivered":8,\#
            "droppedByEndpointSecurity":1,"droppedWhileBehind":2,"skippedWhilePaused":5,"pauses":1}}
            """#
        XCTAssertEqual(StreamReply.decode(Data(stopped.utf8))?.summary,
                       StreamSummary(captured: 9, delivered: 8, droppedByEndpointSecurity: 1, droppedWhileBehind: 2,
                                     skippedWhilePaused: 5, pauses: 1))
        XCTAssertEqual(StreamReply.decode(Data(#"{"version":3,"status":"later","sensorVersion":"3.0 (1)"}"#.utf8))?
                        .status, .unsupported)
        XCTAssertNil(StreamReply.decode(Data(started.utf8))?.stream?.fieldFilters, "From a 3.0.0 Security Extension")
        XCTAssertNil(StreamReply.decode(Data(stopped.utf8))?.summary?.fieldFiltered)
        XCTAssertNil(StreamReply.decode(Data(#"{"version":1,"status":"ok"}"#.utf8)))
        let reply = StreamReply(status: .sessionLimit, problem: "Three streams are running.",
                                sensorVersion: "3.0.0 (1)")
        XCTAssertEqual(StreamReply.decode(reply.encoded()), reply)
    }
    
    /// A 3.1.0 reply says which field filters apply when the stream starts, and what they left out when it stops.
    func testFieldFilterRepliesRead() {
        let started = #"""
            {"version":1,"status":"ok","sensorVersion":"3.1.0 (1)","stream":{"events":["ES_EVENT_TYPE_NOTIFY_CLOSE"],\#
            "fieldFilters":["ES_EVENT_TYPE_NOTIFY_CLOSE.modified"]}}
            """#
        XCTAssertEqual(StreamReply.decode(Data(started.utf8))?.stream,
                       StreamStarted(events: ["ES_EVENT_TYPE_NOTIFY_CLOSE"], savedMutes: nil,
                                     fieldFilters: ["ES_EVENT_TYPE_NOTIFY_CLOSE.modified"]))
        let stopped = #"""
            {"version":1,"status":"ok","sensorVersion":"3.1.0 (1)","summary":{"captured":2,"delivered":2,\#
            "droppedByEndpointSecurity":0,"droppedWhileBehind":0,"skippedWhilePaused":0,"pauses":0,\#
            "fieldFiltered":{"ES_EVENT_TYPE_NOTIFY_CLOSE":7}}}
            """#
        XCTAssertEqual(StreamReply.decode(Data(stopped.utf8))?.summary?.fieldFiltered,
                       ["ES_EVENT_TYPE_NOTIFY_CLOSE": 7])
    }
}

