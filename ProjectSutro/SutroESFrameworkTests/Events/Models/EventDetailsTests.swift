//
//  EventDetailsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Event details
/// Pins which tabs Event Facts' Details box shows for an event, their counts, which tab shows first, and the facts a
/// network flow adds above them.
final class EventDetailsTests: XCTestCase {
    /// The names of a process's own audit tokens, in order.
    private let processTokens = ["Process audit token", "Responsible audit token", "Parent audit token"]

    /// An exec's details: an environment of 2, CS_VALID, CS_RUNTIME and CS_SIGNED, and 2 file descriptors.
    ///
    /// - Returns: The details, with the exec's target as the process it acted on.
    /// - Throws: The error reading the record.
    private func execDetails() throws -> EventDetails {
        var record = try esloggerExec(parent: (1, 1), env: ["PATH=/usr/bin", "HOME=/var/root"])
        record[path: "event", "exec", "target", "codesigning_flags"] = 0x2001_0001
        let exec = try importRecord(record)
        return withStoredEvent(exec) { message in
            message.event.exec?.fds = [Self.vnode(0), Self.vnode(1)]
            return EventDetails(message: message, target: message.event.exec?.target)
        }
    }

    /// An exit's details, an event without a process it acted on.
    ///
    /// - Parameter change: Changes the stored exit before its details are read.
    /// - Returns: The details.
    /// - Throws: The error reading the record.
    private func exitDetails(_ change: (ESMessage) -> Void = { _ in }) throws -> EventDetails {
        let process = try esloggerProcess(pid: 500, pidversion: 5000, path: "/bin/ls", parent: (401, 4010))
        let exit = try exitMessage(of: process)
        return withStoredEvent(exit) { message in
            change(message)
            return EventDetails(message: message, target: nil)
        }
    }

    /// A vnode file descriptor.
    ///
    /// - Parameter number: The descriptor's number.
    /// - Returns: The descriptor.
    private static func vnode(_ number: Int32) -> FileDescriptor {
        var fd = es_fd_t()
        fd.fd = number
        fd.fdtype = UInt32(PROX_FDTYPE_VNODE)
        return FileDescriptor(from: fd)
    }

    /// A stored exec shows all four tabs, in order, each with its count.
    func testStoredExec() throws {
        let details = try execDetails()
        XCTAssertEqual(details.tabs, [.environment, .auditTokens, .codeSigningFlags, .fileDescriptors])
        XCTAssertEqual(details.tabs.map { details.count(of: $0) }, [2, 6, 3, 2])
        XCTAssertEqual(details.auditTokens.map(\.name), processTokens + [
            "Target audit token", "Target responsible audit token", "Target parent audit token",
        ])
        XCTAssertEqual(details.codeSigningFlags.map(\.name), ["CS_VALID", "CS_RUNTIME", "CS_SIGNED"])
    }

    /// An event without a process it acted on shows its process's 3 audit tokens alone.
    func testEventWithoutATarget() throws {
        let details = try exitDetails()
        XCTAssertEqual(details.tabs, [.auditTokens])
        XCTAssertEqual(details.auditTokens.map(\.name), processTokens)
    }

    /// An empty audit token is left out of the count.
    func testEmptyTokenIsSkipped() throws {
        let details = try exitDetails { $0.process.responsible_audit_token_string = "" }
        XCTAssertEqual(details.auditTokens.map(\.name), ["Process audit token", "Parent audit token"])
        XCTAssertEqual(details.count(of: .auditTokens), 2)
    }

    /// The tab picked last shows when the event has it. Otherwise, or before one is picked, the first tab shows.
    func testShownTab() throws {
        let exec = try execDetails()
        let exit = try exitDetails()
        XCTAssertEqual(exec.shownTab(picked: .codeSigningFlags), .codeSigningFlags)
        XCTAssertEqual(exit.shownTab(picked: .codeSigningFlags), .auditTokens)
        XCTAssertEqual(exec.shownTab(picked: nil), .environment)
        XCTAssertEqual(exit.shownTab(picked: nil), .auditTokens)
    }

    /// A process without audit tokens has no tabs, so no tab shows.
    func testNoDetails() throws {
        let details = try exitDetails {
            $0.process.audit_token_string = ""
            $0.process.responsible_audit_token_string = ""
            $0.process.parent_audit_token_string = ""
        }
        XCTAssertEqual(details.tabs, [])
        XCTAssertNil(details.shownTab(picked: .auditTokens))
        XCTAssertTrue(details.isEmpty)
    }

    /// An Endpoint Security event's details have no facts above their tabs.
    func testEndpointSecurityEventsHaveNoFacts() throws {
        XCTAssertEqual(try execDetails().facts, [])
        XCTAssertEqual(try exitDetails().facts, [])
        XCTAssertFalse(try exitDetails().isEmpty)
    }

    /// A network flow's details are its identifier and when it opened, then its process's audit token alone, which a
    /// process whose token wasn't read doesn't have.
    func testNetworkFlow() {
        for kind in [FlowRecord.Kind.opened, .closed] {
            let flow = withStoredEvent(SyntheticFlows.message(SyntheticFlows.record(kind))) {
                EventDetails(message: $0, target: nil)
            }
            XCTAssertEqual(flow.facts.map(\.name), ["Flow ID", "Opened"])
            XCTAssertEqual(flow.tabs, [.auditTokens])
            XCTAssertEqual(flow.auditTokens.map(\.name), ["Process audit token"])
            let token = SyntheticFlows.process().token.map(AuditToken.init(from:))
            XCTAssertEqual(flow.auditTokens.first?.token, token?.toString())
        }
        let reaped = SyntheticFlows.record(.opened, process: SyntheticFlows.process(state: .reaped))
        let unread = withStoredEvent(SyntheticFlows.message(reaped)) { EventDetails(message: $0, target: nil) }
        XCTAssertEqual(unread.facts.map(\.name), ["Flow ID", "Opened"])
        XCTAssertEqual(unread.tabs, [])
        XCTAssertFalse(unread.isEmpty)
    }
}
