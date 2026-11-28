//
//  ProcessLineageTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Process lineage
/// Pins the ancestors the Security Extension keeps for each process, against what Endpoint Security reported on
/// macOS 27.2 for a shell that ran Python, which spawned, forked and orphaned children: a fork gives the child its
/// parent's program, an exec keeps the ancestors under a new key, and an exit forgets only the process itself.
final class ProcessLineageTests: XCTestCase {
    var lineage = ProcessLineage()

    /// A fresh table.
    override func setUp() {
        super.setUp()
        lineage = ProcessLineage()
    }

    /// A key.
    ///
    /// - Parameters:
    ///   - pid: The pid.
    ///   - version: The pid version.
    /// - Returns: The key.
    func key(_ pid: Int32, _ version: Int32) -> ProcessKey {
        ProcessKey(pid: pid, pidversion: version)
    }

    /// A program with a path and a command line.
    ///
    /// - Parameters:
    ///   - pid: Its pid.
    ///   - version: Its pid version.
    ///   - path: Its executable's path.
    /// - Returns: The program.
    func program(_ pid: Int32, _ version: Int32, _ path: String) -> ProcessProgram {
        ProcessProgram(key: key(pid, version), path: path, commandLine: "\(path) --flag", signingID: "com.example",
                       teamID: "TEAM", codesigningType: "DEVELOPER_ID")
    }

    /// The paths of a process's ancestors.
    ///
    /// - Parameters:
    ///   - key: The process.
    ///   - parent: Its parent as its event names it.
    /// - Returns: Each ancestor's path, nearest first, or its key for one known by nothing else.
    func ancestors(of key: ProcessKey, parent: ProcessKey? = nil) -> [String] {
        lineage.ancestors(of: key, parent: parent).map { $0.path ?? $0.key.description }
    }

    /// sshd's shell forks and execs Python, through two launchers that exec in place. Python then spawns `true`.
    /// Its ancestors are Python, the shell and sshd: the launchers Python's pid ran before aren't among them.
    func testAForkThenExecsKeepsTheAncestors() {
        lineage.seed([(program(43367, 103217, "/usr/sbin/sshd"), 1), (program(43371, 103222, "/bin/zsh"), 43367)])
        lineage.fork(key(43372, 103223), from: key(43371, 103222))
        XCTAssertEqual(lineage.program(key(43372, 103223))?.path, "/bin/zsh",
                       "A forked child runs its parent's program")
        lineage.exec(program(43372, 103224, "/usr/bin/python3"), replacing: key(43372, 103223), at: 0)
        lineage.exec(program(43372, 103225, "/Library/CLT/python3"), replacing: key(43372, 103224), at: 0)
        lineage.exec(program(43372, 103226, "/Library/CLT/Python"), replacing: key(43372, 103225), at: 0)
        XCTAssertEqual(ancestors(of: key(43372, 103226)), ["/bin/zsh", "/usr/sbin/sshd"])

        lineage.fork(key(43373, 103227), from: key(43372, 103226))
        lineage.exec(program(43373, 103228, "/usr/bin/true"), replacing: key(43373, 103227), at: 0)
        XCTAssertEqual(ancestors(of: key(43373, 103228)), ["/Library/CLT/Python", "/bin/zsh", "/usr/sbin/sshd"])
        XCTAssertEqual(lineage.ancestors(of: key(43373, 103228)).first,
                       program(43372, 103226, "/Library/CLT/Python"))
    }

    /// A parent that execs again after forking a child stays, for that child, the program that forked it. A child
    /// it forks afterwards has the new program as its parent.
    func testAParentThatExecsAgain() {
        lineage.seed([(program(100, 1, "/bin/bash"), 1)])
        lineage.fork(key(200, 2), from: key(100, 1))
        lineage.exec(program(100, 3, "/bin/sh"), replacing: key(100, 1), at: 0)
        lineage.exec(program(200, 4, "/bin/sleep"), replacing: key(200, 2), at: 0)
        lineage.fork(key(300, 5), from: key(100, 3))
        XCTAssertEqual(ancestors(of: key(200, 4)), ["/bin/bash"])
        XCTAssertEqual(ancestors(of: key(300, 5)), ["/bin/sh"])
    }

    /// A process whose parent exited keeps its ancestors, where Endpoint Security would name launchd. The parent
    /// itself is forgotten once it has lingered, and found until then.
    func testAnOrphanKeepsItsAncestors() {
        lineage.seed([(program(100, 1, "/usr/bin/python3"), 1)])
        lineage.fork(key(200, 2), from: key(100, 1))
        lineage.exec(program(200, 3, "/bin/sh"), replacing: key(200, 2), at: 0)
        lineage.fork(key(300, 4), from: key(200, 3))
        lineage.exit(key(200, 3), at: 5)
        XCTAssertEqual(lineage.program(key(200, 3))?.path, "/bin/sh", "It lingers")
        XCTAssertEqual(ancestors(of: key(200, 3)), ["/usr/bin/python3"])

        lineage.exit(key(999, 1), at: 5 + ProcessLineage.lingers)
        XCTAssertNil(lineage.program(key(200, 3)))
        XCTAssertNil(lineage.program(key(200, 2)), "The program it ran before went when it exec'd")
        lineage.fork(key(400, 5), from: key(300, 4))
        XCTAssertEqual(ancestors(of: key(400, 5)), ["/bin/sh", "/bin/sh", "/usr/bin/python3"])
        XCTAssertEqual(lineage.ancestors(of: key(400, 5)).map(\.key), [key(300, 4), key(200, 3), key(100, 1)])
    }

    /// Of a chain longer than the depth, the nearest ancestors and the first below launchd are listed.
    func testALongChainKeepsItsFirstBelowLaunchd() {
        lineage.seed([(program(10, 1, "/origin"), 1)])
        for pid in Int32(11)...30 {
            lineage.fork(key(pid, 1), from: key(pid - 1, 1))
        }
        let chain = lineage.ancestors(of: key(30, 1)).map(\.key.pid)
        XCTAssertEqual(chain, [29, 28, 27, 26, 25, 24, 23, 10])
        XCTAssertEqual(chain.count, ProcessLineage.depth)
        XCTAssertEqual(lineage.ancestors(of: key(18, 1)).map(\.key.pid), [17, 16, 15, 14, 13, 12, 11, 10])
    }

    /// launchd and the kernel are never listed: a child of launchd has no ancestors, whether it was running
    /// already, exec'd without its fork being seen, or was forked by launchd and then exec'd, as launchd's jobs are.
    func testLaunchdIsNotAnAncestor() {
        lineage.seed([(program(1, 7, "/sbin/launchd"), 0), (program(50, 1, "/usr/libexec/agent"), 1)])
        XCTAssertNil(lineage.program(key(1, 7)))
        XCTAssertEqual(ancestors(of: key(50, 1)), [])
        lineage.exec(program(60, 2, "/usr/libexec/job"), replacing: key(60, 1), parent: key(1, 7), at: 0)
        XCTAssertEqual(ancestors(of: key(60, 2)), [])
        XCTAssertEqual(lineage.count, 2)

        lineage.fork(key(70, 1), from: key(1, 7))
        XCTAssertNil(lineage.program(key(1, 7)))
        XCTAssertEqual(lineage.program(key(70, 1)), ProcessProgram(key: key(70, 1)))
        XCTAssertEqual(ancestors(of: key(70, 1)), [])
        lineage.exec(program(70, 2, "/usr/sbin/sshd"), replacing: key(70, 1), parent: key(1, 7), at: 0)
        lineage.fork(key(80, 3), from: key(70, 2))
        XCTAssertEqual(ancestors(of: key(80, 3)), ["/usr/sbin/sshd"])
        XCTAssertEqual(ancestors(of: key(90, 1), parent: key(1, 7)), [])
    }

    /// Telling the table of the same fork and exec twice, as its own client and a capture lane do, leaves every
    /// process with the ancestors it had, and nothing behind once they've lingered.
    func testTheSameEventsTwice() {
        lineage.seed([(program(100, 1, "/bin/zsh"), 1)])
        let events: [() -> Void] = [
            { self.lineage.fork(self.key(200, 2), from: self.key(100, 1)) },
            { self.lineage.exec(self.program(200, 3, "/bin/sh"), replacing: self.key(200, 2),
                                parent: self.key(100, 1), at: 0) },
            { self.lineage.fork(self.key(300, 4), from: self.key(200, 3)) },
            { self.lineage.exec(self.program(300, 5, "/usr/bin/true"), replacing: self.key(300, 4),
                                parent: self.key(200, 3), at: 0) },
        ]
        events.forEach { $0() }
        events.forEach { $0() }
        XCTAssertEqual(ancestors(of: key(300, 5)), ["/bin/sh", "/bin/zsh"])
        XCTAssertEqual(ancestors(of: key(200, 3)), ["/bin/zsh"])
        XCTAssertEqual(lineage.count, 5)
        lineage.exit(key(300, 5), at: ProcessLineage.lingers)
        XCTAssertEqual(lineage.count, 3, "The programs the two pids ran before their execs are forgotten")
    }

    /// The ancestors along a chain.
    ///
    /// - Parameters:
    ///   - key: The process.
    ///   - chain: The chain.
    /// - Returns: Each ancestor's path, nearest first.
    private func ancestors(of key: ProcessKey, along chain: ProcessLineage.Chain) -> [String] {
        lineage.ancestors(of: key, chain: chain).map { $0.path ?? $0.key.description }
    }

    /// The launched-by chain follows the process that really caused each one to run, and the one that forked it
    /// where there's none: a service launchd forked has its host app, and the app's own ancestors. A child the
    /// service forks has the service, then the app. The Unix chain is unchanged.
    func testTheLaunchedByChainFollowsLaunchers() {
        lineage.seed([(program(50, 1, "/usr/bin/open"), 1), (program(100, 1, "/Applications/Host.app"), 50)])
        lineage.fork(key(200, 1), from: key(1, 7))
        lineage.exec(program(200, 2, "/Helper.xpc"), replacing: key(200, 1), parent: key(1, 7),
                     launchedBy: key(100, 1), at: 0)
        lineage.fork(key(300, 3), from: key(200, 2))
        XCTAssertEqual(ancestors(of: key(200, 2), along: .lineage), [])
        XCTAssertEqual(ancestors(of: key(200, 2), along: .launchedBy), ["/Applications/Host.app", "/usr/bin/open"])
        XCTAssertEqual(ancestors(of: key(300, 3), along: .lineage), ["/Helper.xpc"])
        XCTAssertEqual(ancestors(of: key(300, 3), along: .launchedBy),
                       ["/Helper.xpc", "/Applications/Host.app", "/usr/bin/open"])
        XCTAssertEqual(ancestors(of: key(100, 1), along: .launchedBy), ["/usr/bin/open"])
    }

    /// A second telling of an exec or a fork that doesn't say who launched the process keeps what the first said.
    /// Launch Services' later answer replaces it. A launcher known only by its pid is found by its pid, one that's
    /// launchd ends the chain, one the table doesn't know leaves the process with the one that forked it, and two
    /// that name each other end the chain where it comes round.
    func testWhoLaunchedAProcess() {
        lineage.seed([(program(100, 1, "/Applications/Host.app"), 1), (program(110, 1, "/Applications/Other.app"), 1),
                      (program(120, 4, "/bin/zsh"), 1)])
        lineage.fork(key(200, 1), from: key(120, 4), launchedBy: key(100, 1))
        lineage.fork(key(200, 1), from: key(120, 4))
        XCTAssertEqual(ancestors(of: key(200, 1), along: .launchedBy), ["/Applications/Host.app"])
        lineage.exec(program(200, 2, "/Helper.xpc"), replacing: key(200, 1), launchedBy: key(100, 1), at: 0)
        lineage.exec(program(200, 2, "/Helper.xpc"), replacing: key(200, 1), at: 0)
        XCTAssertEqual(ancestors(of: key(200, 2), along: .launchedBy), ["/Applications/Host.app"])
        XCTAssertEqual(ancestors(of: key(200, 2), along: .lineage), ["/bin/zsh"])

        lineage.setLauncher(key(110, 1), of: key(200, 2))
        XCTAssertEqual(ancestors(of: key(200, 2), along: .launchedBy), ["/Applications/Other.app"])
        lineage.setLauncher(key(120, 0), of: key(200, 2))
        XCTAssertEqual(ancestors(of: key(200, 2), along: .launchedBy), ["/bin/zsh"], "By its pid alone")
        lineage.setLauncher(key(1, 7), of: key(200, 2))
        XCTAssertEqual(ancestors(of: key(200, 2), along: .launchedBy), [])
        lineage.setLauncher(key(999, 1), of: key(200, 2))
        XCTAssertEqual(ancestors(of: key(200, 2), along: .launchedBy), ["/bin/zsh"])
        lineage.setLauncher(nil, of: key(200, 2))
        XCTAssertEqual(ancestors(of: key(200, 2), along: .launchedBy), ["/bin/zsh"])
        lineage.setLauncher(key(555, 5), of: key(777, 7))

        lineage.setLauncher(key(110, 1), of: key(100, 1))
        lineage.setLauncher(key(100, 1), of: key(110, 1))
        lineage.setLauncher(key(100, 1), of: key(200, 2))
        XCTAssertEqual(ancestors(of: key(200, 2), along: .launchedBy),
                       ["/Applications/Host.app", "/Applications/Other.app"])
    }

    /// Seeding fills in what events left unknown and adds what's missing, and what an event said stands.
    func testSeedingFillsInWhatIsMissing() {
        lineage.fork(key(200, 2), from: key(100, 1))
        lineage.exec(program(200, 3, "/bin/sleep"), replacing: key(200, 2), at: 0)
        XCTAssertEqual(ancestors(of: key(200, 3)), ["100.1"])

        lineage.seed([(program(50, 1, "/usr/sbin/sshd"), 1), (program(100, 1, "/bin/zsh"), 50),
                      (program(200, 3, "/seeded/over/an/event"), 100), (program(200, 1, "/an/older/program"), 100)])
        XCTAssertEqual(ancestors(of: key(200, 3)), ["/bin/zsh", "/usr/sbin/sshd"])
        XCTAssertEqual(lineage.program(key(200, 3))?.path, "/bin/sleep")
        XCTAssertNil(lineage.program(key(200, 1)), "The pid runs a newer program than the list says")
    }

    /// A process the list names is added even when the table holds an older program of its pid, and emptying the
    /// table forgets everything.
    func testSeedingOverAnOlderProgram() {
        lineage.fork(key(200, 2), from: key(100, 1))
        lineage.seed([(program(200, 5, "/bin/newer"), 1), (program(300, 1, "/bin/child"), 200)])
        XCTAssertEqual(lineage.program(key(200, 5))?.path, "/bin/newer")
        XCTAssertEqual(ancestors(of: key(300, 1)), ["/bin/newer"])
        lineage.removeAll()
        XCTAssertEqual(lineage.count, 0)
        XCTAssertEqual(ancestors(of: key(300, 1)), [])
    }

    /// A pid the system used again is another process, with its own ancestors.
    func testAReusedPid() {
        lineage.seed([(program(100, 1, "/bin/zsh"), 1), (program(101, 1, "/bin/bash"), 1)])
        lineage.fork(key(200, 2), from: key(100, 1))
        lineage.exit(key(200, 2), at: 0)
        lineage.fork(key(200, 9), from: key(101, 1))
        XCTAssertEqual(ancestors(of: key(200, 2)), ["/bin/zsh"])
        XCTAssertEqual(ancestors(of: key(200, 9)), ["/bin/bash"])
        lineage.exit(key(200, 9), at: ProcessLineage.lingers)
        XCTAssertNil(lineage.program(key(200, 2)))
        XCTAssertNotNil(lineage.program(key(200, 9)))
    }

    /// A key reads back from what a record writes, and nothing else reads as one.
    func testAKeyAsARecordWritesIt() {
        XCTAssertEqual(key(43372, 103226).description, "43372.103226")
        XCTAssertEqual(ProcessKey("43372.103226"), key(43372, 103226))
        XCTAssertEqual(ProcessKey("0.0"), key(0, 0))
        for text in ["", "43372", "43372.", ".5", "1.2.3", "a.b", "-1.2", "1.-2", "99999999999.1", " 1.2"] {
            XCTAssertNil(ProcessKey(text), text)
        }
    }

    /// Forks, execs, exits and lookups from many threads at once leave the table whole, and empty of everything
    /// that exited once it has lingered.
    func testManyThreads() {
        lineage.seed([(program(2, 1, "/root"), 1)])
        DispatchQueue.concurrentPerform(iterations: 8) { thread in
            let base = Int32(1_000 * (thread + 1))
            for index in Int32(0)..<500 {
                let child = key(base + index, 1), image = key(base + index, 2)
                lineage.fork(child, from: key(2, 1))
                lineage.exec(program(image.pid, 2, "/bin/tool"), replacing: child, at: 0)
                XCTAssertEqual(lineage.ancestors(of: image).map(\.key), [key(2, 1)])
                lineage.exit(image, at: 0)
            }
        }
        XCTAssertEqual(lineage.count, 1 + 8 * 500 * 2)
        lineage.exit(key(2, 1), at: ProcessLineage.lingers)
        XCTAssertEqual(lineage.count, 1)
        lineage.exit(key(7, 7), at: ProcessLineage.lingers * 2)
        XCTAssertEqual(lineage.count, 0)
    }
}
