//
//  FlowProcessResolverTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - A flow's process
/// Pins how a socket's process is told apart: by the unique ID the kernel gave the socket, matched against the pid's
/// even when it's a zombie, with what's read while it lives, what the lineage table knows, and, on delivery, what the
/// table learns after.
final class FlowProcessResolverTests: XCTestCase {
    private let reads = FakeFlowReads()

    /// Give pid 100 a live process with a parent, group and session.
    override func setUp() {
        super.setUp()
        reads.processes = [100: FakeFlowReads.Process(upid: 5_000, pidversion: 7, ppid: 50, groupID: 100,
                                                       sessionID: 40)]
    }

    /// A live process whose unique ID matches is exact, with its token, parent, group, session and signing values.
    func testALiveMatch() throws {
        let process = FlowProcessResolver(reads: reads.reads).resolve(pid: 100, upid: 5_000, name: "curl")
        XCTAssertEqual(process.state, .live)
        XCTAssertEqual(process.key, ProcessKey(pid: 100, pidversion: 7))
        XCTAssertEqual(process.token.map(ProcessKey.init), ProcessKey(pid: 100, pidversion: 7))
        XCTAssertEqual([process.ppid, process.groupID, process.sessionID], [50, 100, 40])
        XCTAssertEqual(process.program, ProcessProgram(key: ProcessKey(pid: 100, pidversion: 7), path: "/usr/bin/curl",
                                                       signingID: "com.apple.curl", codesigningType: "PLATFORM"))
    }

    /// A pid whose unique ID isn't the socket's was reused: the process is gone, and nothing is read of the other.
    /// Neither is anything of the kernel's sockets.
    func testAMismatchOrTheKernel() {
        let resolver = FlowProcessResolver(reads: reads.reads)
        let cases: [(Int32, UInt64, FlowProcess.State)] = [(100, 5_001, .reaped), (200, 1, .reaped), (0, 0, .kernel)]
        for (pid, upid, state) in cases {
            let process = resolver.resolve(pid: pid, upid: upid, name: "curl")
            XCTAssertEqual(process.state, state)
            XCTAssertNil(process.key)
            XCTAssertNil(process.token)
            XCTAssertNil(process.ppid)
        }
        XCTAssertEqual(reads.signingReads, 0)
    }

    /// A descriptor with no unique ID, as a delegated TCP socket's effective pid has, names the process that has the
    /// pid now, live or zombie, by its own unique ID. A pid with no process stays reaped, and so does a unique ID that
    /// doesn't match.
    func testNoUniqueIDNamesThePidsProcess() {
        let resolver = FlowProcessResolver(reads: reads.reads)
        let live = resolver.resolve(pid: 100, upid: 0, name: "")
        let key = ProcessKey(pid: 100, pidversion: 7)
        XCTAssertEqual(live.state, .live)
        XCTAssertEqual(live.key, key)
        XCTAssertEqual(live.token.map(ProcessKey.init), key)
        XCTAssertEqual(live.program, ProcessProgram(key: key, path: "/usr/bin/curl", signingID: "com.apple.curl",
                                                    codesigningType: "PLATFORM"))
        XCTAssertEqual(resolver.resolve(pid: 100, upid: 5_000, name: "curl").key, key)
        XCTAssertEqual(reads.signingReads, 1, "Cached by its own unique ID")
        reads.processes[300] = FakeFlowReads.Process(upid: 6_000, pidversion: 9, isZombie: true)
        let zombie = resolver.resolve(pid: 300, upid: 0, name: "")
        XCTAssertEqual(zombie.state, .zombie)
        XCTAssertEqual(zombie.key, ProcessKey(pid: 300, pidversion: 9))
        for (pid, upid) in [(200, 0), (100, 5_001)] as [(Int32, UInt64)] {
            let process = resolver.resolve(pid: pid, upid: upid, name: "")
            XCTAssertEqual(process.state, .reaped, "\(pid) \(upid)")
            XCTAssertNil(process.key)
        }
    }

    /// A zombie has its exact key, parent and group, and nothing a live process alone gives: no session, token or
    /// signing values, unless the lineage table knows its program.
    func testAZombie() {
        reads.processes[100]?.isZombie = true
        let process = FlowProcessResolver(reads: reads.reads).resolve(pid: 100, upid: 5_000, name: "curl")
        XCTAssertEqual(process.state, .zombie)
        XCTAssertEqual(process.key, ProcessKey(pid: 100, pidversion: 7))
        XCTAssertEqual([process.ppid, process.groupID], [50, 100])
        XCTAssertNil(process.sessionID)
        XCTAssertNil(process.token)
        XCTAssertNil(process.program)
        let key = ProcessKey(pid: 100, pidversion: 7)
        reads.programs[key] = ProcessProgram(key: key, path: "/usr/bin/curl", codesigningType: "PLATFORM")
        XCTAssertEqual(FlowProcessResolver(reads: reads.reads).resolve(pid: 100, upid: 5_000, name: "curl").program,
                       reads.programs[key])
    }

    /// A process that exec'd between the identity read and the token read has a token of its new program, which
    /// isn't kept, so nothing of the new program is read for the old.
    func testAnExecBetweenReads() {
        reads.processes[100]?.tokenVersion = 8
        let process = FlowProcessResolver(reads: reads.reads).resolve(pid: 100, upid: 5_000, name: "curl")
        XCTAssertEqual(process.key, ProcessKey(pid: 100, pidversion: 7))
        XCTAssertNil(process.token)
        XCTAssertNil(process.program)
    }

    /// A process is read once by its unique ID, again after it execs, and asked of the lineage table again while
    /// it has no signing values.
    func testTheCacheRevalidates() {
        let resolver = FlowProcessResolver(reads: reads.reads)
        _ = resolver.resolve(pid: 100, upid: 5_000, name: "curl")
        _ = resolver.resolve(pid: 100, upid: 5_000, name: "curl")
        XCTAssertEqual(reads.signingReads, 1)
        reads.processes[100]?.pidversion = 8
        XCTAssertEqual(resolver.resolve(pid: 100, upid: 5_000, name: "zsh").key?.pidversion, 8)
        XCTAssertEqual(reads.signingReads, 2)
        reads.processes[100]?.signing = nil
        reads.processes[100]?.pidversion = 9
        XCTAssertNil(resolver.resolve(pid: 100, upid: 5_000, name: "zsh").program?.codesigningType)
        let key = ProcessKey(pid: 100, pidversion: 9)
        reads.programs[key] = ProcessProgram(key: key, path: "/bin/zsh", codesigningType: "PLATFORM")
        XCTAssertEqual(resolver.resolve(pid: 100, upid: 5_000, name: "zsh").program, reads.programs[key])
    }

    /// A program the lineage table knows is taken from it, with its exec's values, and nothing is read.
    func testTheLineageTablesProgram() {
        let key = ProcessKey(pid: 100, pidversion: 7)
        reads.programs[key] = ProcessProgram(key: key, path: "/usr/bin/curl", commandLine: "curl https://example.com",
                                             signingID: "com.apple.curl", codesigningType: "PLATFORM")
        XCTAssertEqual(FlowProcessResolver(reads: reads.reads).resolve(pid: 100, upid: 5_000, name: "curl").program,
                       reads.programs[key])
        XCTAssertEqual(reads.signingReads, 0)
    }

    /// The kernel's flags tell a platform binary, an adhoc and an unsigned one, and a Developer ID or App Store
    /// one's certificates do. Live: this Mac's `sleep` is a platform binary, and this test process's signature reads.
    func testSigningValues() throws {
        let certificates: (String) -> CodeSigningType = { _ in .developerId }
        let valid = UInt32(CS_VALID)
        let platform = valid | UInt32(CS_PLATFORM_BINARY), adhoc = valid | UInt32(CS_ADHOC)
        XCTAssertEqual(FlowSigning.type(flags: platform, path: "/x", certificates: certificates), .platform)
        XCTAssertEqual(FlowSigning.type(flags: adhoc, path: "/x", certificates: certificates), .adhoc)
        XCTAssertEqual(FlowSigning.type(flags: 0, path: "/x", certificates: certificates), .unsigned)
        XCTAssertEqual(FlowSigning.type(flags: valid, path: "/x", certificates: certificates), .developerId)
        XCTAssertEqual(FlowSigning.type(flags: valid, path: "", certificates: certificates), .unsigned)

        let sleep = Process()
        sleep.executableURL = URL(fileURLWithPath: "/bin/sleep")
        sleep.arguments = ["10"]
        try sleep.run()
        defer { sleep.terminate() }
        let token = try XCTUnwrap(RunningProcesses.token(of: sleep.processIdentifier))
        XCTAssertEqual(FlowSigning.read(token, path: "/bin/sleep"),
                       FlowSigning(signingID: "com.apple.sleep", teamID: nil, type: .platform))
        var stale = token
        stale.val.7 += 1
        XCTAssertNil(FlowSigning.read(stale, path: "/bin/sleep"), "The kernel checks the pid version")
        XCTAssertNotNil(FlowSigning.read(audit_token_t.currentProcess, path: ""))
    }

    /// On delivery, a process with a key but no token takes the lineage table's, once the table is told of the
    /// flow's time, and a reaped one the pid's newest program when its name starts with the socket's.
    func testCompletionFromTheLineageTable() {
        let lineage = ProcessLineage(reader: nil, patience: 0.05)
        let key = ProcessKey(pid: 100, pidversion: 7)
        let token = RawMessageFixture.auditToken(pid: 100, pidversion: 7)
        lineage.exec(ProcessProgram(key: key, path: "/usr/bin/curl", codesigningType: "PLATFORM"),
                     replacing: ProcessKey(pid: 100, pidversion: 6), token: token, at: 0)
        var zombie = FlowProcess(pid: 100, name: "curl", state: .zombie, key: key)
        XCTAssertTrue(zombie.complete(from: lineage, upTo: 0))
        XCTAssertEqual(zombie.program?.path, "/usr/bin/curl")
        XCTAssertEqual(zombie.token.map(ProcessKey.init), key)
        var reaped = FlowProcess(pid: 100, name: "curl", state: .reaped)
        XCTAssertTrue(reaped.complete(from: lineage, upTo: 0))
        XCTAssertEqual(reaped.program?.key, key)
        var renamed = FlowProcess(pid: 100, name: "wget", state: .reaped)
        XCTAssertFalse(renamed.complete(from: lineage, upTo: 0))
        XCTAssertNil(renamed.program)
        var unknown = FlowProcess(pid: 300, name: "curl", state: .reaped)
        XCTAssertFalse(unknown.complete(from: lineage, upTo: 0))
    }
}
