//
//  PeerSignatureTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The routing hint
/// The process ID check the router uses to pick a role: it reads a running process's real signature, and anything it
/// can't check is `false`.
final class PeerSignatureTests: XCTestCase {
    /// launchd is Apple's, and this test process isn't `macmonitor`.
    func testItReadsTheRunningProcess() {
        XCTAssertTrue(PeerSignature.satisfies("anchor apple and identifier \"com.apple.xpc.launchd\"",
                                              processIdentifier: 1))
        XCTAssertFalse(PeerSignature.satisfies(SensorXPC.commandLineRequirement, processIdentifier: getpid()))
        XCTAssertFalse(PeerSignature.isCommandLine(FakePeer(euid: geteuid(), pid: getpid())))
    }

    /// No process, or a requirement that doesn't compile, is never a match.
    func testWhatCantBeCheckedIsFalse() {
        XCTAssertFalse(PeerSignature.satisfies("anchor apple", processIdentifier: 0))
        XCTAssertFalse(PeerSignature.satisfies("anchor apple", processIdentifier: -1))
        XCTAssertFalse(PeerSignature.satisfies("not a requirement (", processIdentifier: 1))
    }
}
