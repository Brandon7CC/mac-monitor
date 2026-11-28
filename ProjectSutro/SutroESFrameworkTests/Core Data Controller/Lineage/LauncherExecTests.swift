//
//  LauncherExecTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/27/26.
//

import XCTest
import CoreData
@testable import SutroESFramework


// MARK: - The launcher's exec
/// Pins the exec Event Facts compares an exec's environment with: the first exec among its ancestors, nearest first,
/// past the forks between them.
final class LauncherExecTests: XCTestCase {
    /// A shell (401) forks a child (470) that execs git, and git forks a child (480) that execs `sh`, as git runs a
    /// hook. Login's exec of the shell isn't stored.
    ///
    /// - Returns: The shell's exec, its fork, git's exec, git's fork, and the `sh` exec, in order.
    /// - Throws: The error reading a fixture.
    private func gitHook() throws -> [Message] {
        let child = try esloggerProcess(pid: 470, pidversion: 4700, path: "/bin/zsh", parent: (401, 4010))
        let git = try esloggerProcess(pid: 470, pidversion: 4701, path: "/usr/bin/git", parent: (401, 4010))
        let gitChild = try esloggerProcess(pid: 480, pidversion: 4800, path: "/usr/bin/git", parent: (470, 4701))
        let sh = try esloggerProcess(pid: 480, pidversion: 4801, path: "/bin/sh", parent: (470, 4701))
        return [try shellExec(), try forkMessage(by: try shell(), of: child), try execMessage(by: child, of: git),
                try forkMessage(by: git, of: gitChild), try execMessage(by: gitChild, of: sh)]
    }

    /// Store events, and read them back in the view context, where Event Facts looks them up.
    ///
    /// - Parameter messages: The events.
    /// - Returns: The store, and the stored events in order.
    /// - Throws: The error fetching the events.
    private func inserted(_ messages: [Message]) throws -> (CoreDataController, [ESMessage]) {
        let store = CoreDataController(model: eventModel)
        let saved = expectation(description: "saved")
        store.insertSystemEvents(messages: messages) { saved.fulfill() }
        wait(for: [saved], timeout: 60)
        let stored = try messages.map { message in
            let request = NSFetchRequest<ESMessage>(entityName: "ESMessage")
            request.predicate = NSPredicate(format: "id == %@", message.id as CVarArg)
            return try XCTUnwrap(try store.container.viewContext.fetch(request).first)
        }
        return (store, stored)
    }

    /// An exec's launcher is the exec before the fork that made its process: git's for the hook, the shell's for git.
    func testTheFirstExecPastTheForks() throws {
        let (store, stored) = try inserted(try gitHook())
        XCTAssertEqual(store.launcherExec(of: stored[4])?.objectID, stored[2].objectID)
        XCTAssertEqual(store.launcherExec(of: stored[2])?.objectID, stored[0].objectID)
        XCTAssertEqual(store.getProcTree(targetEvent: stored[4]).map(\.objectID),
                       [stored[3], stored[2], stored[1], stored[0]].map(\.objectID))
    }

    /// An exec whose ancestors the store doesn't have has no launcher, and neither has one whose only ancestor is a
    /// fork.
    func testNoLauncher() throws {
        let (store, stored) = try inserted(try gitHook())
        XCTAssertNil(store.launcherExec(of: stored[0]))
        let (forkOnly, events) = try inserted(Array(try gitHook().dropFirst()))
        XCTAssertNil(forkOnly.launcherExec(of: events[1]))
    }

    /// The hook's environment is compared with git's, named by its executable and pid.
    func testTheHookIsComparedWithGit() throws {
        let (store, stored) = try inserted(try gitHook())
        let variables = EnvironmentVariable.variables(in: ["PATH=/bin"])
        let launcher = store.launcherExec(of: stored[4])
        XCTAssertEqual(try XCTUnwrap(EnvironmentComparison(variables, launcherExec: launcher)).launcher, "git (470)")
    }
}
