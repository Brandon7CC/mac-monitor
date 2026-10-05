//
//  ProcessParentsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import CoreData
@testable import SutroESFramework


// MARK: - The Parents box
/// Pins what Event Facts' Parents box shows for an exec or fork: the Unix parent as the message names it, the
/// launched-by parent beside it, and when the two are one.
final class ProcessParentsTests: XCTestCase {
    /// A shell's child has one parent: the shell, named by its exec, is both. So does the fork that made the child,
    /// whose Unix parent is the forking process exactly.
    ///
    /// - Throws: The error reading or storing the events.
    func testShellChildHasOneParent() throws {
        try withEventStore(try lineageTrace(after: [try shellExec()])) { context, stored in
            let lookup = LineageLookup(context)
            let exec = try XCTUnwrap(lookup.parents(of: stored[2]))
            XCTAssertEqual(exec.unix.pid, 401)
            XCTAssertEqual(exec.unix.original_ppid, 401)
            XCTAssertEqual(exec.unix.path, "/bin/zsh")
            XCTAssertEqual(exec.launchedByParent?.event?.objectID, stored[0].objectID)
            XCTAssertTrue(exec.launchedByParentIsUnixParent)
            
            let fork = try XCTUnwrap(lookup.parents(of: stored[1]))
            XCTAssertEqual(fork.unix.pid, 401)
            XCTAssertEqual(fork.unix.path, "/bin/zsh")
            XCTAssertEqual(fork.launchedByParent?.launchedByParent.source, .unixParent)
            XCTAssertTrue(fork.launchedByParentIsUnixParent)
        }
    }
    
    /// A Unix parent the trace has no exec for is named by the launched-by parent, when that's the same process.
    ///
    /// - Throws: The error reading or storing the events.
    func testUnixParentNamedByTheAnswer() throws {
        try withEventStore(try lineageTrace()) { context, stored in
            let parents = try XCTUnwrap(LineageLookup(context).parents(of: stored[1]))
            XCTAssertEqual(parents.unix.pid, 401)
            XCTAssertEqual(parents.unix.path, "/bin/zsh")
            XCTAssertNil(parents.launchedByParent?.event)
            XCTAssert(parents.launchedByParentIsUnixParent)
        }
    }
    
    /// An app, an XPC service and a launchd job have launchd as their Unix parent and another launched-by parent beside
    /// it.
    ///
    /// - Throws: The error reading or storing the events.
    func testLaunchdChildrenHaveTwoParents() throws {
        var messages = try lineageTrace()
        let launcher = AuditToken(pid: 410, pidversion: 4102, asid: 100_001, auid: 4_294_967_295, euid: 0, ruid: 0,
                                  rgid: 0, egid: 0)
        messages[5].setLaunchedByParent(LaunchedByParent(source: .launchServices, audit_token: launcher, path: nil,
                                                         launchd_job: .init(label: Self.lineageAppLabel),
                                                         resolved_by: .app))
        try withEventStore(messages) { context, stored in
            let lookup = LineageLookup(context)
            let expected: [(index: Int, source: LaunchedByParent.Source, pid: Int32, event: ESMessage?)] = [
                (5, .launchServices, 410, stored[4]), (6, .responsibleProcess, 500, stored[5]),
                (4, .launchdJob, 1, nil),
            ]
            for (index, source, pid, event) in expected {
                let parents = try XCTUnwrap(lookup.parents(of: stored[index]), "event \(index)")
                XCTAssertEqual(parents.unix.pid, 1, "event \(index)")
                XCTAssertEqual(parents.unix.path, LaunchedByParent.launchdPath, "event \(index)")
                XCTAssertEqual(parents.launchedByParent?.launchedByParent.source, source, "event \(index)")
                XCTAssertEqual(parents.launchedByParent?.launchedByParent.pid, pid, "event \(index)")
                XCTAssertEqual(parents.launchedByParent?.event?.objectID, event?.objectID, "event \(index)")
                XCTAssertFalse(parents.launchedByParentIsUnixParent, "event \(index)")
            }
        }
    }
    
    /// A process launchd adopted before its exec has launchd as its Unix parent and its original parent, by pid, as
    /// its launched-by parent.
    ///
    /// - Throws: The error reading or storing the events.
    func testReparentedProcessKeepsItsOriginalParent() throws {
        try withEventStore(try lineageTrace()) { context, stored in
            let parents = try XCTUnwrap(LineageLookup(context).parents(of: stored[7]))
            XCTAssertEqual(parents.unix.pid, 1)
            XCTAssertEqual(parents.unix.original_ppid, 401)
            XCTAssertEqual(parents.unix.path, LaunchedByParent.launchdPath)
            XCTAssertEqual(parents.launchedByParent?.launchedByParent.source, .unixParent)
            XCTAssertEqual(parents.launchedByParent?.launchedByParent.pid, 401)
            XCTAssertFalse(parents.launchedByParentIsUnixParent)
        }
    }
    
    /// Only an exec or a fork has parents to show.
    ///
    /// - Throws: The error reading or storing the events.
    func testOtherEventsHaveNone() throws {
        try withEventStore([try exitMessage(of: try shell())]) { context, stored in
            XCTAssertNil(LineageLookup(context).parents(of: stored[0]))
        }
    }
}
