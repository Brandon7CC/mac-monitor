//
//  ProcessLineageFlowTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - What flows ask of the lineage table
/// Pins what a flow's delivery asks of the lineage table: the token each program was told of, and lookups that wait
/// until the table's own client is told of an event as late as the flow.
final class ProcessLineageFlowTests: XCTestCase {
    /// - Parameters:
    ///   - pid: The pid.
    ///   - version: The pid version.
    /// - Returns: The key.
    private func key(_ pid: Int32, _ version: Int32) -> ProcessKey {
        ProcessKey(pid: pid, pidversion: version)
    }

    /// - Parameters:
    ///   - pid: The pid.
    ///   - version: The pid version.
    /// - Returns: The token.
    private func token(_ pid: Int32, _ version: UInt32) -> audit_token_t {
        RawMessageFixture.auditToken(pid: pid, pidversion: version)
    }

    /// Each program keeps the token it was told of: a seeded process's, a fork's child's and an exec's target's.
    /// A second telling without one keeps it.
    func testProgramsKeepTheirTokens() {
        let lineage = ProcessLineage()
        lineage.seed([(ProcessProgram(key: key(100, 1), path: "/bin/zsh"), 1, token(100, 1))])
        let fork = rawMessage(type: ES_EVENT_TYPE_NOTIFY_FORK)
        fork.message.pointee.process.pointee.audit_token = token(100, 1)
        fork.fork(childPID: 0, parent: token(100, 1), responsible: token(100, 1)).pointee.audit_token = token(200, 2)
        lineage.note(fork.message, at: 0)
        let exec = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXEC)
        exec.message.pointee.process.pointee.audit_token = token(200, 2)
        let target = exec.process(path: "/usr/bin/curl")
        (target.pointee.audit_token, target.pointee.parent_audit_token) = (token(200, 3), token(100, 1))
        exec.message.pointee.event.exec.target = target
        lineage.note(exec.message, at: 0) { _ in [] }
        for key in [key(100, 1), key(200, 2), key(200, 3)] {
            XCTAssertEqual(lineage.program(key, toldUpTo: 0)?.token.map(ProcessKey.init), key)
        }
        lineage.exec(ProcessProgram(key: key(200, 3), path: "/usr/bin/curl"), replacing: key(200, 2), at: 0)
        XCTAssertNotNil(lineage.program(key(200, 3), toldUpTo: 0)?.token, "A second telling keeps it")
        XCTAssertEqual(lineage.newestProgram(of: 200, toldUpTo: 0)?.program.key, key(200, 3))
    }

    /// A lookup for a flow's program waits for its exec, which the table can hear of after the flow, and stops
    /// once the table is told of an event as late as the flow. One that waits in vain is charged to the budget.
    func testLookupsWaitUntilToldOfTheFlow() {
        let lineage = ProcessLineage(reader: nil, patience: 0.5, waitBudget: 0.3)
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) {
            lineage.exec(ProcessProgram(key: self.key(300, 2), path: "/usr/bin/nscurl"), replacing: self.key(300, 1),
                         token: self.token(300, 2), at: 0)
        }
        XCTAssertEqual(lineage.program(key(300, 2), toldUpTo: 500)?.program.path, "/usr/bin/nscurl")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) { lineage.told(upTo: 600) }
        let began = Date()
        XCTAssertNil(lineage.newestProgram(of: 400, toldUpTo: 600))
        XCTAssertLessThan(Date().timeIntervalSince(began), 0.4, "Told, it stops waiting")
        XCTAssertNil(lineage.program(key(400, 1), toldUpTo: 1_000))
        XCTAssertEqual(lineage.waits.count, 3)
        let spent = Date()
        XCTAssertNil(lineage.program(key(400, 1), toldUpTo: 1_000))
        XCTAssertLessThan(Date().timeIntervalSince(spent), 0.1, "The second's budget is spent")
    }
}
