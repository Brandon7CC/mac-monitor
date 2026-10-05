//
//  ProcessPathMemoryTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Process path memory
/// Pins how a capture lane and a trace import remember process executables for naming launched-by parents: exactly by
/// pid and pid version, read at most once per process, and bounded without losing the processes still in use.
final class ProcessPathMemoryTests: XCTestCase {
    /// A shell, its later image, and another shell that reused its pid.
    private let shell = AuditToken.fixture(pid: 401, pidversion: 4010)
    private let shellAfterExec = AuditToken.fixture(pid: 401, pidversion: 4011)
    
    /// A path is remembered for exactly one process image: a reused pid, or the same pid after an exec, isn't it. An
    /// image's executable never changes, so the first path remembered for it stays.
    func testRemembersByProcessImage() {
        let memory = ProcessPathMemory(capacity: 8)
        memory.remember(shell, path: "/bin/zsh")
        memory.remember(shellAfterExec, path: "/usr/bin/true")
        memory.remember(shell, path: "/bin/sh")
        XCTAssertEqual(memory.path(of: AuditToken(from: RawMessageFixture.auditToken(pid: 401, pidversion: 4010))),
                       "/bin/zsh", "whatever the token's id")
        XCTAssertEqual(memory.path(of: shellAfterExec), "/usr/bin/true")
        XCTAssertNil(memory.path(of: .fixture(pid: 402, pidversion: 4010)))
        XCTAssertNil(memory.path(of: nil))
        let other = AuditToken.fixture(pid: 403, pidversion: 4030)
        memory.remember(nil, path: "/bin/zsh")
        memory.remember(other, path: nil)
        XCTAssertNil(memory.path(of: other), "nothing is remembered without a token and a path")
    }
    
    /// A process's path is read once, then remembered under its token; without a token it's read every time.
    func testReadsOncePerProcess() {
        let memory = ProcessPathMemory(capacity: 8)
        var reads: [Int32] = []
        let read = { (pid: Int32, _: AuditToken?) -> String? in
            reads.append(pid)
            return "/read/\(pid)"
        }
        XCTAssertEqual(memory.path(of: 401, shell, reading: read), "/read/401")
        XCTAssertEqual(memory.path(of: 401, shell, reading: read), "/read/401")
        XCTAssertEqual(memory.path(of: 401, nil, reading: read), "/read/401")
        XCTAssertEqual(memory.path(of: 401, nil, reading: read), "/read/401")
        XCTAssertEqual(reads, [401, 401, 401])
        XCTAssertNil(memory.path(of: 499, .fixture(pid: 499, pidversion: 1)) { _, _ in nil })
    }
    
    /// Past its capacity the memory drops its older generation, but keeps a process looked up again.
    func testBoundedByGenerations() {
        let memory = ProcessPathMemory(capacity: 2)
        let tokens = (501...504).map { AuditToken.fixture(pid: $0, pidversion: 1) }
        memory.remember(tokens[0], path: "/a")
        memory.remember(tokens[1], path: "/b")
        memory.remember(tokens[2], path: "/c")
        XCTAssertEqual(memory.path(of: tokens[0]), "/a", "the older generation, moved to the newer one")
        memory.remember(tokens[3], path: "/d")
        XCTAssertNil(memory.path(of: tokens[1]), "dropped with the older generation")
        XCTAssertEqual(memory.path(of: tokens[0]), "/a")
        XCTAssertEqual(memory.path(of: tokens[2]), "/c")
        XCTAssertEqual(memory.path(of: tokens[3]), "/d")
    }
    
    /// An exec names its new image and a fork its forking process: the processes that can go on to be parents. Other
    /// events name nothing.
    ///
    /// - Throws: The error reading a record.
    func testRemembersExecsAndForksOnly() throws {
        let memory = ProcessPathMemory(capacity: 8)
        let exit = try importRecord(try fixtureObject("eslogger-exit.jsonl"))
        memory.remember(processesOf: exit)
        XCTAssertNil(memory.path(of: exit.process.audit_token))
        
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_FORK)
        fixture.fork(childPID: 402, parent: RawMessageFixture.auditToken(pid: 401, pidversion: 4010),
                     responsible: RawMessageFixture.auditToken(pid: 300, pidversion: 3000))
        memory.remember(processesOf: Message(from: fixture.raw))
        XCTAssertEqual(memory.path(of: shell), "/usr/bin/true")
        XCTAssertNil(memory.path(of: .fixture(pid: 402, pidversion: 1)), "the child")
        
        let exec = try importRecord(try esloggerExec(parent: (401, 4010)))
        memory.remember(processesOf: exec)
        XCTAssertEqual(memory.path(of: exec.event.exec?.target.audit_token), "/usr/libexec/exampled")
    }
}
