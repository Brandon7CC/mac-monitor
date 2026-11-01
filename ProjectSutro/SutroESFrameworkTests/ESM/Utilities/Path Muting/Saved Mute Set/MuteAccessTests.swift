//
//  MuteAccessTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Who may change the saved mute set
/// Pins who may change the saved mute set from Mac Monitor: any user's Mac Monitor, administrator or not, while it owns
/// the event stream or nobody does. Everyone else may list it.
final class MuteAccessTests: XCTestCase {
    /// A Mac Monitor that controls the stream may change the set, whoever its user is: a standard user's (502) as much
    /// as an administrator's (501). Another connection while someone owns the stream, or no connection, only lists it.
    func testAnyUsersMacMonitorThatControlsTheStreamMayChangeIt() {
        let owner = FakePeer(euid: 501), standardUser = FakePeer(euid: 502), other = FakePeer(euid: 501)
        XCTAssertEqual(MuteAccess.app(owner, owner: owner), .write)
        XCTAssertEqual(MuteAccess.app(standardUser, owner: standardUser), .write)
        XCTAssertEqual(MuteAccess.app(standardUser, owner: nil), .write)
        XCTAssertEqual(MuteAccess.app(other, owner: owner), .read, "Same user, another connection")
        XCTAssertEqual(MuteAccess.app(standardUser, owner: owner), .read)
        XCTAssertEqual(MuteAccess.app(nil, owner: nil), .read)
        XCTAssertEqual(MuteAccess.app(nil, owner: owner), .read)
    }

    /// Read refuses changes and says why. Write refuses nothing.
    func testRefusals() {
        XCTAssertNil(MuteAccess.write.refusal)
        XCTAssertEqual(MuteAccess.read.refusal?.status, .refused)
        XCTAssertTrue(MuteAccess.read.refusal?.problem.contains("owns the event stream") == true)
    }

    /// A connection controls the event stream when it owns it, or when nobody does. A connection that isn't the
    /// owner, or no connection at all, doesn't while someone does.
    func testOnlyTheStreamsOwnerControlsIt() {
        let owner = FakePeer(euid: 501), other = FakePeer(euid: 501)
        XCTAssertTrue(MuteAccess.controlsStream(owner, owner: owner))
        XCTAssertTrue(MuteAccess.controlsStream(other, owner: nil))
        XCTAssertTrue(MuteAccess.controlsStream(nil, owner: nil))
        XCTAssertFalse(MuteAccess.controlsStream(other, owner: owner), "Same user, another connection")
        XCTAssertFalse(MuteAccess.controlsStream(nil, owner: owner))
    }
}
