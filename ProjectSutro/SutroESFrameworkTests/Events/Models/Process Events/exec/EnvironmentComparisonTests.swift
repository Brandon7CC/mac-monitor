//
//  EnvironmentComparisonTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/27/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Environment comparison
/// Pins how Event Facts compares an exec's environment with its launcher's: which variables differ, which names are
/// unset, the names shells set for each command, and the words the Environment section shows.
final class EnvironmentComparisonTests: XCTestCase {
    /// An exec's environment compared with a baseline, by a launcher named `git (38070)`.
    ///
    /// - Parameters:
    ///   - env: The exec's environment.
    ///   - baseline: The launcher's environment.
    /// - Returns: The comparison.
    private func compare(_ env: [String], with baseline: [String]) -> EnvironmentComparison {
        EnvironmentComparison(EnvironmentVariable.variables(in: env), launcher: "git (38070)",
                              baseline: EnvironmentVariable.variables(in: baseline))
    }

    /// - Parameter comparison: A comparison.
    /// - Returns: The positions that differ, in order.
    private func differing(_ comparison: EnvironmentComparison) -> [Int] {
        comparison.differing.sorted()
    }

    /// The `sh` git ran for `core.fsmonitor`: four variables git added or changed differ, and the ones shells set
    /// don't, though their values changed.
    func testAGitHook() {
        let git = ["HOME=/Users/user", "PATH=/usr/bin:/bin", "PWD=/Users/user", "OLDPWD=/", "SHLVL=1",
                   "_=/usr/bin/git", "LANG=C.UTF-8"]
        let sh = ["HOME=/Users/user", "GIT_CONFIG_PARAMETERS='core.fsmonitor'='/w/fsmonitor.sh'",
                  "GIT_EXEC_PATH=/Library/Developer/CommandLineTools/usr/libexec/git-core", "GIT_PREFIX=",
                  "PATH=/Library/Developer/CommandLineTools/usr/libexec/git-core:/usr/bin:/bin", "PWD=/w",
                  "OLDPWD=/Users/user", "SHLVL=2", "_=/bin/sh", "LANG=C.UTF-8"]
        let comparison = compare(sh, with: git)
        XCTAssertEqual(differing(comparison), [1, 2, 3, 4])
        XCTAssertEqual(comparison.unset, [])
        XCTAssertEqual(comparison.reading, "4 differ from git (38070)")
        XCTAssertEqual(comparison.same, "6 the same as when git (38070) started")
        XCTAssertEqual(comparison.help, "Compared with the environment git (38070) had at its own exec. PWD, OLDPWD, "
                       + "SHLVL and _ aren't counted: shells set them for each command.")
    }

    /// The launcher's first variable of a name is the one compared, and each of the exec's is compared with it.
    func testTheBaselinesFirstOccurrenceCounts() {
        XCTAssertEqual(differing(compare(["A=2"], with: ["A=1", "A=2"])), [0])
        XCTAssertEqual(differing(compare(["A=1"], with: ["A=1", "A=2"])), [])
        XCTAssertEqual(differing(compare(["A=1", "A=2"], with: ["A=1"])), [1])
    }

    /// A name the launcher didn't have differs, even with an empty value, and so does a value that's only emptied.
    func testANewOrEmptiedVariableDiffers() {
        XCTAssertEqual(differing(compare(["NEW=", "OLD="], with: ["OLD=x"])), [0, 1])
        XCTAssertEqual(differing(compare(["FLAG"], with: ["FLAG"])), [])
    }

    /// Names the launcher had and the exec doesn't are unset, once each and in the launcher's order, without the ones
    /// shells set. The help names them.
    func testUnsetNames() {
        let comparison = compare(["A=1"], with: ["HISTFILE=/h", "A=1", "PWD=/", "_=/bin/zsh", "TERM=x", "HISTFILE=/i"])
        XCTAssertEqual(comparison.unset, ["HISTFILE", "TERM"])
        XCTAssertEqual(comparison.reading, "same as git (38070)")
        XCTAssertTrue(comparison.help.hasSuffix(" 2 unset: HISTFILE, TERM."), comparison.help)
    }

    /// None are the same when every variable differs, as an xpcproxy service's variables often do. One variable the
    /// same, or none differing, leaves some the same.
    func testEveryVariableDifferingLeavesNothingToShowAll() {
        XCTAssertFalse(compare(["OSLogRateLimit=64", "XPC_FLAGS=19"], with: ["PATH=/usr/bin"]).hasSame)
        XCTAssertTrue(compare(["A=2", "B=1"], with: ["A=1", "B=1"]).hasSame)
        XCTAssertTrue(compare(["A=1"], with: ["A=1"]).hasSame)
    }

    /// One difference reads in the singular.
    func testOneDifference() {
        let comparison = compare(["A=2", "B=1"], with: ["A=1", "B=1"])
        XCTAssertEqual(comparison.reading, "1 differs from git (38070)")
        XCTAssertEqual(comparison.same, "1 the same as when git (38070) started")
        XCTAssertTrue(comparison.differs(EnvironmentVariable("A=2", at: 0)))
        XCTAssertFalse(comparison.differs(EnvironmentVariable("B=1", at: 1)))
    }

    /// A launcher read from the store is named by its executable and pid, and there's no comparison without one or
    /// with an event that isn't an exec.
    func testLauncherFromTheStore() throws {
        let variables = EnvironmentVariable.variables(in: ["PATH=/bin", "HOME=/var/root"])
        let launcher = try importRecord(try esloggerExec(parent: (1, 1), env: ["PATH=/usr/bin", "HOME=/var/root"]))
        let comparison = try XCTUnwrap(withStoredEvent(launcher) {
            EnvironmentComparison(variables, launcherExec: $0)
        })
        XCTAssertEqual(comparison.launcher, "exampled (4242)")
        XCTAssertEqual(differing(comparison), [0])
        XCTAssertNil(EnvironmentComparison(variables, launcherExec: nil))
        let exit = try exitMessage(of: try shell())
        XCTAssertNil(withStoredEvent(exit) { EnvironmentComparison(variables, launcherExec: $0) })
    }
}
