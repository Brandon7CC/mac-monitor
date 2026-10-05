//
//  PipelineScopeTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Pipeline scope
/// Pins which events `macmonitor` leaves out as its own pipeline's: its own process always, and with `--include-self`
/// only that; otherwise its group and every consecutive `sudo` ancestor's, never the shell's, never 0 or launchd's.
final class PipelineScopeTests: XCTestCase {
    private let sudo = PipelineScope.sudoPath
    
    /// A header for an event from a process.
    ///
    /// - Parameters:
    ///   - pid: The process ID.
    ///   - group: Its process group.
    /// - Returns: The header.
    private func event(pid: Int32, group: Int32) -> EventHeader {
        EventHeader(sequence: nil, globalSequence: nil, eventType: 9, name: "ES_EVENT_TYPE_NOTIFY_EXEC",
                    time: "2026-10-05T01:02:03.004005006Z",
                    process: EventHeader.Process(pid: pid, groupID: group, user: "root", path: "/usr/bin/jq"),
                    context: nil, targetPath: nil)
    }
    
    /// sudo with `use_pty` (1.9.14 and later): `macmonitor` in the monitor's new session, the monitor, then the sudo
    /// in the shell's pipeline group with `jq`. All three groups are suppressed, the shell's isn't.
    func testSudoWithAPseudoTerminal() {
        let scope = PipelineScope(ancestry: [
            PipelineAncestor(pid: 900, groupID: 900, path: "/Applications/Mac Monitor.app/Contents/MacOS/macmonitor"),
            PipelineAncestor(pid: 899, groupID: 899, path: sudo),
            PipelineAncestor(pid: 898, groupID: 898, path: sudo),
            PipelineAncestor(pid: 500, groupID: 500, path: "/bin/zsh")
        ], includeSelf: false)
        XCTAssertEqual(scope.groups, [900, 899, 898])
        XCTAssertTrue(scope.suppresses(event(pid: 901, group: 898)), "jq, in the pipeline's group")
        XCTAssertFalse(scope.suppresses(event(pid: 500, group: 500)), "the shell")
    }
    
    /// sudo without a pseudo-terminal, and a root shell without sudo: one group, the pipeline's.
    func testOneGroup() {
        let plain = PipelineScope(ancestry: [PipelineAncestor(pid: 900, groupID: 898, path: "/x/macmonitor"),
                                             PipelineAncestor(pid: 898, groupID: 898, path: sudo),
                                             PipelineAncestor(pid: 500, groupID: 500, path: "/bin/zsh")],
                                  includeSelf: false)
        XCTAssertEqual(plain.groups, [898])
        let rootShell = PipelineScope(ancestry: [PipelineAncestor(pid: 900, groupID: 900, path: "/x/macmonitor"),
                                                 PipelineAncestor(pid: 500, groupID: 500, path: "/bin/zsh")],
                                      includeSelf: false)
        XCTAssertEqual(rootShell.groups, [900])
    }
    
    /// Nested sudo walks through every sudo; a sudo above another program doesn't count.
    func testOnlyConsecutiveSudosCount() {
        let scope = PipelineScope(ancestry: [PipelineAncestor(pid: 900, groupID: 900, path: "/x/macmonitor"),
                                             PipelineAncestor(pid: 899, groupID: 899, path: sudo),
                                             PipelineAncestor(pid: 700, groupID: 700, path: "/bin/sh"),
                                             PipelineAncestor(pid: 600, groupID: 600, path: sudo)],
                                  includeSelf: false)
        XCTAssertEqual(scope.groups, [900, 899])
    }
    
    /// Groups 0 and 1 (the kernel's and launchd's) are never suppressed, whatever the ancestry says.
    func testLaunchdsGroupIsNeverSuppressed() {
        let scope = PipelineScope(ancestry: [PipelineAncestor(pid: 900, groupID: 1, path: "/x/macmonitor"),
                                             PipelineAncestor(pid: 1, groupID: 0, path: sudo)],
                                  includeSelf: false)
        XCTAssertEqual(scope.groups, [])
        XCTAssertTrue(scope.suppresses(event(pid: 900, group: 1)), "macmonitor itself")
        XCTAssertFalse(scope.suppresses(event(pid: 77, group: 1)))
    }
    
    /// With `--include-self`, only `macmonitor`'s own process is left out.
    func testIncludeSelfKeepsOnlyOwnProcessOut() {
        let scope = PipelineScope(ancestry: [PipelineAncestor(pid: 900, groupID: 898, path: "/x/macmonitor"),
                                             PipelineAncestor(pid: 898, groupID: 898, path: sudo)],
                                  includeSelf: true)
        XCTAssertEqual(scope.groups, [])
        XCTAssertTrue(scope.suppresses(event(pid: 900, group: 898)))
        XCTAssertFalse(scope.suppresses(event(pid: 901, group: 898)))
    }
    
    /// The live walk starts at this process with its real group, and stops after the first ancestor that isn't sudo.
    func testTheLiveWalk() throws {
        let ancestry = PipelineScope.ancestry(from: getpid())
        let own = try XCTUnwrap(ancestry.first)
        XCTAssertEqual(own.pid, getpid())
        XCTAssertEqual(own.groupID, getpgrp())
        XCTAssertFalse(own.path.isEmpty)
        XCTAssertEqual(ancestry.dropFirst().dropLast().filter { $0.path != PipelineScope.sudoPath }, [])
        XCTAssertTrue(PipelineScope.current(includeSelf: false).groups.contains(getpgrp()) || getpgrp() <= 1)
        XCTAssertEqual(PipelineScope.current(includeSelf: true).ownPID, getpid())
    }
}
