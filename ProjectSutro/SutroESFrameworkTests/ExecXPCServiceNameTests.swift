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
    /// The value of the `XPC_SERVICE_NAME` entry is the name.
    func testServiceName() {
        XCTAssertEqual(ESProcessExecEvent.xpcServiceName(in: ["PATH=/usr/bin", "XPC_SERVICE_NAME=com.example.agent"]),
                       "com.example.agent")
    }
    
    /// launchd's `0` (not an XPC service), an empty value, and no entry at all are no name.
    func testNoServiceName() {
        XCTAssertNil(ESProcessExecEvent.xpcServiceName(in: ["XPC_SERVICE_NAME=0"]))
        XCTAssertNil(ESProcessExecEvent.xpcServiceName(in: ["XPC_SERVICE_NAME="]))
        XCTAssertNil(ESProcessExecEvent.xpcServiceName(in: []))
    }
    
    /// Only an entry named exactly `XPC_SERVICE_NAME` counts: not a longer name, nor the text inside another value.
    func testOnlyTheExactNameCounts() {
        XCTAssertNil(ESProcessExecEvent.xpcServiceName(in: ["XPC_SERVICE_NAME_EXTRA=1"]))
        XCTAssertNil(ESProcessExecEvent.xpcServiceName(in: ["FOO=XPC_SERVICE_NAME=com.example.agent"]))
    }
    
    /// The first entry wins, as it does for `getenv`.
    func testFirstEntryWins() {
        XCTAssertEqual(ESProcessExecEvent.xpcServiceName(in: ["XPC_SERVICE_NAME=a", "XPC_SERVICE_NAME=b"]), "a")
    }
    
    /// A stored exec event finds the name in its own environment, as Event Facts read it.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the fixture has no process.
    func testStoredExecEvent() throws {
        var record = try fixtureObject("eslogger-exit.jsonl")
        let exec: [String: Any] = [
            "target": try XCTUnwrap(record["process"]), "script": NSNull(), "dyld_exec_path": "/usr/libexec/exampled",
            "cwd": ["path": "/", "path_truncated": false, "stat": [:]], "last_fd": 2, "image_cputype": 16_777_228,
            "image_cpusubtype": 2, "args": ["/usr/libexec/exampled"], "fds": [],
            "env": ["PATH=/usr/bin:/bin", "XPC_SERVICE_NAME=com.example.agent"],
        ]
        record["event"] = ["exec": exec]
        record["event_type"] = 9
        let message = try importRecord(record)
        XCTAssertEqual(withStoredEvent(message) { $0.event.exec?.xpcServiceName }, "com.example.agent")
    }
}
