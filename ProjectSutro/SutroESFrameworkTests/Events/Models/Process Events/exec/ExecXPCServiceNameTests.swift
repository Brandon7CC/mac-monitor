//
//  ExecXPCServiceNameTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - XPC service name
/// Pins how an exec event's XPC service name is found in its environment, which decides whether Event Facts offer
/// the XPC sheet.
final class ExecXPCServiceNameTests: XCTestCase {
    /// launchd's `0` (not an XPC service), an empty value, and no entry at all are no name.
    func testNoServiceName() {
        XCTAssertNil(ProcessExecEvent.xpcServiceName(in: ["XPC_SERVICE_NAME=0"]))
        XCTAssertNil(ProcessExecEvent.xpcServiceName(in: ["XPC_SERVICE_NAME="]))
        XCTAssertNil(ProcessExecEvent.xpcServiceName(in: []))
    }
    
    /// Only an entry named exactly `XPC_SERVICE_NAME` counts: not a longer name, nor the text inside another value.
    func testOnlyTheExactNameCounts() {
        XCTAssertNil(ProcessExecEvent.xpcServiceName(in: ["XPC_SERVICE_NAME_EXTRA=1"]))
        XCTAssertNil(ProcessExecEvent.xpcServiceName(in: ["FOO=XPC_SERVICE_NAME=com.example.agent"]))
    }
    
    /// The first entry wins, as it does for `getenv`.
    func testFirstEntryWins() {
        XCTAssertEqual(ProcessExecEvent.xpcServiceName(in: ["XPC_SERVICE_NAME=a", "XPC_SERVICE_NAME=b"]), "a")
    }
    
    /// A stored exec event finds the name in its own environment, as Event Facts read it.
    func testStoredExecEvent() throws {
        let env = ["PATH=/usr/bin:/bin", "XPC_SERVICE_NAME=com.example.agent"]
        let message = try importRecord(try esloggerExec(parent: (1, 1), env: env))
        XCTAssertEqual(withStoredEvent(message) { $0.event.exec?.xpcServiceName }, "com.example.agent")
    }
}
