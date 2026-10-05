//
//  MuteRequestTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Mute requests and replies
/// Pins the JSON Mac Monitor, `macmonitor` and the Security Extension exchange about the saved mute set: round trips,
/// and what an older or newer peer makes of the other's messages.
final class MuteRequestTests: XCTestCase {
    /// A request and a reply read back as they were written.
    ///
    /// - Throws: An unexpected ``XPCRequestError``.
    func testRequestAndReplyRoundTrip() throws {
        let request = MuteRequest(.add, [MuteFile.Entry(path: "/a", type: "ES_MUTE_PATH_TYPE_LITERAL",
                                                        events: ["ES_EVENT_TYPE_NOTIFY_OPEN"])])
        XCTAssertEqual(try MuteRequest.decode(request.encoded()), request)
        let reply = MuteReply(status: .refused, changed: false, mutes: request.mutes, problems: ["No."],
                              notice: "Read-only.", access: .read)
        XCTAssertEqual(MuteReply.decode(reply.encoded()), reply)
        let standardUser = MuteReply(status: .notAdministrator, mutes: [], access: .standardUser)
        XCTAssertEqual(MuteReply.decode(standardUser.encoded()), standardUser)
    }
    
    /// A reply missing everything but its version and status still reads, an unknown status reads as unsupported,
    /// and an unknown access as none, so an older Mac Monitor can read a newer Security Extension's reply.
    func testRepliesReadForward() {
        let bare = MuteReply.decode(Data(#"{"version": 1, "status": "ok"}"#.utf8))
        XCTAssertEqual(bare, MuteReply(status: .ok, mutes: []))
        XCTAssertEqual(MuteReply.decode(Data(#"{"version": 2, "status": "renamed", "extra": 1}"#.utf8))?.status,
                       .unsupported)
        XCTAssertNil(MuteReply.decode(Data(#"{"status": "ok"}"#.utf8)))
        let renamed = MuteReply.decode(Data(#"{"version": 1, "status": "ok", "access": "guest"}"#.utf8))
        XCTAssertEqual(renamed, MuteReply(status: .ok, mutes: []))
        XCTAssertNil(renamed?.access)
    }
    
    /// A newer version or an unknown operation is unsupported; missing mutes mean none.
    ///
    /// - Throws: An unexpected ``XPCRequestError``.
    func testNewerRequestsAreUnsupported() throws {
        let newer = Data(#"{"version": 2, "operation": "list"}"#.utf8)
        XCTAssertThrowsError(try MuteRequest.decode(newer)) { error in
            XCTAssertEqual((error as? XPCRequestError)?.status(as: MuteReply.Status.self), .unsupported)
        }
        let unknown = Data(#"{"version": 1, "operation": "frobnicate"}"#.utf8)
        XCTAssertThrowsError(try MuteRequest.decode(unknown)) { error in
            XCTAssertEqual((error as? XPCRequestError)?.status(as: MuteReply.Status.self), .unsupported)
            XCTAssertTrue("\(error)".contains("frobnicate"))
        }
        let bare = Data(#"{"version": 1, "operation": "reset"}"#.utf8)
        XCTAssertEqual(try MuteRequest.decode(bare), MuteRequest(.reset))
    }
    
    /// Text that isn't a request, a version below 1, and a request over 1 MiB, are invalid.
    func testInvalidRequests() {
        let requests = [Data("nope".utf8), Data(#"{"operation": "list"}"#.utf8),
                        Data(#"{"version": 0, "operation": "list"}"#.utf8),
                        Data(#"{"version": -7, "operation": "reset"}"#.utf8),
                        Data(count: MuteLimits.maxFileBytes + 1)]
        for data in requests {
            XCTAssertThrowsError(try MuteRequest.decode(data)) { error in
                XCTAssertEqual((error as? XPCRequestError)?.status(as: MuteReply.Status.self), .invalid)
            }
        }
    }
}
