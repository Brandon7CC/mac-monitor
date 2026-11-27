//
//  ESProcessUnreadTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Values a process didn't have read
/// Pins what Event Facts reads of a stored process whose values weren't all read, as a network flow's may not be: its
/// users without an audit token, its group when it wasn't read, and its File Quarantine type without an executable.
final class ESProcessUnreadTests: XCTestCase {
    /// - Parameter process: A flow's process.
    /// - Returns: Its stored row's users, group and File Quarantine type, as Event Facts reads them.
    private func read(_ process: FlowProcess) -> (hasUsers: Bool, groupID: Int32?, quarantine: String?) {
        withStoredEvent(SyntheticFlows.message(SyntheticFlows.record(.opened, process: process))) {
            ($0.process.hasUsers, $0.process.groupID, $0.process.quarantineType)
        }
    }

    /// A flow's process with its token has its users and group. One reaped before its socket was first reported has
    /// neither, and its zero user IDs and empty File Quarantine type aren't read as root and as quarantine-aware.
    func testAFlowsProcess() {
        let live = read(SyntheticFlows.process())
        XCTAssertTrue(live.hasUsers)
        XCTAssertEqual(live.groupID, 753)
        XCTAssertNil(live.quarantine)
        XCTAssertEqual(read(SyntheticFlows.process(state: .zombie)).groupID, 753)

        let reaped = read(SyntheticFlows.process(state: .reaped))
        XCTAssertFalse(reaped.hasUsers)
        XCTAssertNil(reaped.groupID)
        XCTAssertNil(reaped.quarantine)
        let stored = withStoredEvent(SyntheticFlows.message(SyntheticFlows.record(
            .opened, process: SyntheticFlows.process(state: .reaped)))) {
            ($0.process.euid, $0.process.group_id, $0.process.file_quarantine_type)
        }
        XCTAssertEqual(stored.0, 0)
        XCTAssertEqual(stored.1, Process.unread)
        XCTAssertEqual(stored.2, "")
    }

    /// An Endpoint Security event's process reads as it's stored: its users, its group, and a File Quarantine type
    /// other than `DISABLED`.
    func testAnEndpointSecurityProcess() throws {
        let exit = try exitMessage(of: try shell())
        let read = withStoredEvent(exit) { ($0.process.hasUsers, $0.process.groupID, $0.process.quarantineType) }
        XCTAssertTrue(read.0)
        XCTAssertEqual(read.1, exit.process.group_id)
        XCTAssertNil(read.2)
        let aware = withStoredEvent(exit) { message in
            ["OPT_IN", "FORCED"].map { type in
                message.process.file_quarantine_type = type
                return message.process.quarantineType
            }
        }
        XCTAssertEqual(aware, ["OPT_IN", "FORCED"])
    }

    /// How a flow's process is signed is known from its executable and its code signing type, unsigned included. It
    /// isn't for a reaped process, nor for one whose code signing type wasn't read. It is for an Endpoint Security
    /// process.
    func testHowAProcessIsSignedIsKnown() throws {
        var unsigned = SyntheticFlows.process(signingID: "")
        unsigned.program?.codesigningType = CodeSigningType.unsigned.rawValue
        var unread = SyntheticFlows.process(signingID: "")
        unread.program?.codesigningType = nil
        let processes = [SyntheticFlows.process(), unsigned, SyntheticFlows.process(state: .reaped), unread]
        let known = processes.map { process in
            withStoredEvent(SyntheticFlows.message(SyntheticFlows.record(.opened, process: process))) {
                $0.process.isSigningKnown
            }
        }
        XCTAssertEqual(known, [true, true, false, false])
        XCTAssertTrue(withStoredEvent(try exitMessage(of: try shell())) { $0.process.isSigningKnown })
    }
}
