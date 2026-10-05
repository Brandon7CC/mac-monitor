//
//  LaunchedByParentChainTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import CoreData
@testable import SutroESFramework


// MARK: - Walking up launched-by parents
/// Pins how Event Facts walks a process's launched-by parents through the store: each step's answer, the event that
/// created that parent, and where the walk ends.
final class LaunchedByParentChainTests: XCTestCase {
    /// A step's answer, the event it leads to, and the parent's executable, checked.
    ///
    /// - Parameters:
    ///   - step: The step.
    ///   - source: Its answer's source.
    ///   - pid: Its answer's pid.
    ///   - event: The event that created the parent, or `nil` for none.
    ///   - path: The parent's executable (``LaunchedByParentStep/path``).
    ///   - label: The launchd job's label, if any.
    private func assertStep(_ step: LaunchedByParentStep?, _ source: LaunchedByParent.Source, pid: Int32?,
                            event: ESMessage?, path: String?, label: String? = nil, file: StaticString = #filePath,
                            line: UInt = #line) {
        guard let step else { return XCTFail("No step", file: file, line: line) }
        XCTAssertEqual(step.launchedByParent.source, source, file: file, line: line)
        XCTAssertEqual(step.launchedByParent.pid, pid, file: file, line: line)
        XCTAssertEqual(step.event?.objectID, event?.objectID, file: file, line: line)
        XCTAssertEqual(step.path, path, file: file, line: line)
        XCTAssertEqual(step.launchedByParent.launchd_job?.label, label, file: file, line: line)
    }
    
    /// A shell's child, the fork that made it and its exit all walk up to the shell's exec, then to a parent the trace
    /// doesn't have. A launchd job's child walks up to the job, then to launchd.
    ///
    /// - Throws: The error reading or storing the events.
    func testShellExecForkChain() throws {
        try withEventStore(try lineageTrace(after: [try shellExec()])) { context, stored in
            let lookup = LineageLookup(context)
            for event in [stored[1], stored[2]] {
                let steps = lookup.launchedByParents(of: event)
                XCTAssertEqual(steps.count, 2)
                assertStep(steps.first, .unixParent, pid: 401, event: stored[0], path: "/bin/zsh")
                assertStep(steps.last, .unixParent, pid: 300, event: nil, path: nil)
            }
            let grandchild = lookup.launchedByParents(of: stored[10])
            XCTAssertEqual(grandchild.count, 2)
            assertStep(grandchild.first, .unixParent, pid: 410, event: stored[5], path: "/usr/libexec/exampled")
            assertStep(grandchild.last, .launchdJob, pid: 1, event: nil, path: LaunchedByParent.launchdPath,
                       label: "com.example.agent")
        }
    }
    
    /// An app LaunchServices launched walks up to its launcher's exec, then the launcher's own launched-by parent.
    /// Without a launcher recorded, the walk ends there.
    ///
    /// - Throws: The error reading or storing the events.
    func testAppStepNamesItsLauncher() throws {
        var messages = try lineageTrace()
        let launcher = AuditToken(pid: 410, pidversion: 4102, asid: 100_001, auid: 4_294_967_295, euid: 0, ruid: 0,
                                  rgid: 0, egid: 0)
        let job = LaunchedByParent.LaunchdJob(label: Self.lineageAppLabel)
        messages[5].setLaunchedByParent(LaunchedByParent(source: .launchServices, audit_token: launcher, path: nil,
                                                         launchd_job: job, resolved_by: .app))
        try withEventStore(messages) { context, stored in
            let steps = LineageLookup(context).launchedByParents(of: stored[5])
            XCTAssertEqual(steps.count, 2)
            assertStep(steps.first, .launchServices, pid: 410, event: stored[4], path: "/usr/libexec/exampled",
                       label: Self.lineageAppLabel)
            XCTAssertEqual(steps.first?.launchedByParent.resolved_by, .app)
            assertStep(steps.last, .launchdJob, pid: 1, event: nil, path: LaunchedByParent.launchdPath,
                       label: "com.example.agent")
        }
        messages[5].setLaunchedByParent(LaunchedByParent(source: .launchServices, audit_token: nil, path: nil,
                                                         launchd_job: job, resolved_by: .app))
        try withEventStore(messages) { context, stored in
            let steps = LineageLookup(context).launchedByParents(of: stored[5])
            XCTAssertEqual(steps.count, 1)
            assertStep(steps.first, .launchServices, pid: nil, event: nil, path: nil, label: Self.lineageAppLabel)
        }
    }
    
    /// An XPC service walks up to its host app, then to launchd, which started the app.
    ///
    /// - Throws: The error reading or storing the events.
    func testXPCServiceStepsToItsHost() throws {
        try withEventStore(try lineageTrace()) { context, stored in
            let steps = LineageLookup(context).launchedByParents(of: stored[6])
            XCTAssertEqual(steps.count, 2)
            assertStep(steps.first, .responsibleProcess, pid: 500, event: stored[5],
                       path: "/Applications/Example.app/Contents/MacOS/Example",
                       label: "com.example.App.ExampleService")
            assertStep(steps.last, .launchdJob, pid: 1, event: nil, path: LaunchedByParent.launchdPath,
                       label: Self.lineageAppLabel)
        }
    }
    
    /// launchd ends the walk, named with its job's label when it has one.
    ///
    /// - Throws: The error reading or storing the events.
    func testLaunchdEndsTheWalk() throws {
        try withEventStore(try lineageTrace()) { context, stored in
            let lookup = LineageLookup(context)
            let job = lookup.launchedByParents(of: stored[4])
            XCTAssertEqual(job.count, 1)
            assertStep(job.first, .launchdJob, pid: 1, event: nil, path: LaunchedByParent.launchdPath,
                       label: "com.example.agent")
            for xpcproxy in [stored[2], stored[3], stored[8]] {
                let steps = lookup.launchedByParents(of: xpcproxy)
                XCTAssertEqual(steps.count, 1)
                assertStep(steps.first, .unixParent, pid: 1, event: nil, path: LaunchedByParent.launchdPath)
            }
        }
    }
    
    /// A parent the trace doesn't have ends the walk, still named by what the trace says about it.
    ///
    /// - Throws: The error reading or storing the events.
    func testParentMissingFromTheTrace() throws {
        try withEventStore(try lineageTrace()) { context, stored in
            let steps = LineageLookup(context).launchedByParents(of: stored[1])
            XCTAssertEqual(steps.count, 1)
            assertStep(steps.first, .unixParent, pid: 401, event: nil, path: "/bin/zsh")
            XCTAssertEqual(steps.first?.launchedByParent.audit_token?.pidversion, 4010)
        }
    }
    
    /// A process launchd adopted before its exec names its original parent by pid alone. The walk finds that parent's
    /// exec back through the process's earlier image to the fork that created it, and only for a fork by that pid.
    ///
    /// - Throws: The error reading or storing the events.
    func testReparentedParentIsFoundThroughTheFork() throws {
        let child = try esloggerProcess(pid: 430, pidversion: 4299, path: "/bin/zsh", parent: (401, 4010))
        let image = try esloggerProcess(pid: 430, pidversion: 4300, path: "/bin/zsh", parent: (401, 4010))
        let earlier = [try shellExec(), try forkMessage(by: try shell(), of: child),
                       try execMessage(by: child, of: image)]
        try withEventStore(try lineageTrace(after: earlier)) { context, stored in
            let steps = LineageLookup(context).launchedByParents(of: stored[10])
            XCTAssertEqual(steps.count, 2)
            assertStep(steps.first, .unixParent, pid: 401, event: stored[0], path: "/bin/zsh")
            XCTAssertNil(steps.first?.launchedByParent.audit_token)
            assertStep(steps.last, .unixParent, pid: 300, event: nil, path: nil)
        }
        let stranger = try esloggerProcess(pid: 402, pidversion: 4020, path: "/bin/zsh", parent: (401, 4010))
        let other = [try shellExec(), try forkMessage(by: stranger, of: child), try execMessage(by: child, of: image)]
        try withEventStore(try lineageTrace(after: other)) { context, stored in
            let steps = LineageLookup(context).launchedByParents(of: stored[10])
            XCTAssertEqual(steps.count, 1)
            assertStep(steps.first, .unixParent, pid: 401, event: nil, path: nil)
        }
    }
    
    /// A parent already walked ends the walk, and so do 64 steps or the caller's limit.
    ///
    /// - Throws: The error reading or storing the events.
    func testWalkEndsAtARepeatAndAfter64Steps() throws {
        let first = try esloggerProcess(pid: 501, pidversion: 5010, path: "/usr/bin/true", parent: (502, 5020))
        let second = try esloggerProcess(pid: 502, pidversion: 5020, path: "/bin/zsh", parent: (501, 5010))
        var cycle = [try execMessage(by: first, of: first), try execMessage(by: second, of: second)]
        TraceLaunchedByParents().fill(&cycle)
        try withEventStore(cycle) { context, stored in
            let steps = LineageLookup(context).launchedByParents(of: stored[0])
            XCTAssertEqual(steps.count, 1)
            assertStep(steps.first, .unixParent, pid: 502, event: stored[1], path: "/bin/zsh")
        }
        
        var chain = try (0..<70).map { index in
            let process = try esloggerProcess(pid: 400 + index, pidversion: 1, path: "/bin/zsh",
                                              parent: (399 + index, 1))
            return try execMessage(by: process, of: process)
        }
        TraceLaunchedByParents().fill(&chain)
        try withEventStore(chain) { context, stored in
            let lookup = LineageLookup(context)
            let steps = lookup.launchedByParents(of: stored[69])
            XCTAssertEqual(steps.count, LineageLookup.maxSteps)
            assertStep(steps.first, .unixParent, pid: 468, event: stored[68], path: "/bin/zsh")
            assertStep(steps.last, .unixParent, pid: 405, event: stored[5], path: "/bin/zsh")
            XCTAssertEqual(lookup.launchedByParents(of: stored[69], limit: 1).count, 1)
            XCTAssertEqual(lookup.launchedByParents(of: stored[3]).count, 4, "Ends at a parent the store doesn't have")
        }
    }
    
    /// Any other event starts from the process that caused it: its first step is that process's launched-by parent.
    ///
    /// - Throws: The error reading or storing the events.
    func testOtherEventsStartFromTheirProcess() throws {
        let job = try esloggerProcess(pid: 410, pidversion: 4102, path: "/usr/libexec/exampled", parent: (1, 1))
        let unknown = try esloggerProcess(pid: 490, pidversion: 4900, path: "/usr/bin/true", parent: (1, 1))
        let messages = try lineageTrace() + [try exitMessage(of: job), try exitMessage(of: unknown)]
        try withEventStore(messages) { context, stored in
            let lookup = LineageLookup(context)
            XCTAssertEqual(lookup.creator(ofProcessOf: stored[10])?.objectID, stored[4].objectID)
            let steps = lookup.launchedByParents(of: stored[10], limit: 1)
            XCTAssertEqual(steps.count, 1)
            XCTAssertEqual(steps.first?.launchedByParent, stored[4].createdLaunchedByParent)
            XCTAssertNil(lookup.creator(ofProcessOf: stored[11]))
            XCTAssertTrue(lookup.launchedByParents(of: stored[11]).isEmpty)
        }
    }
    
    /// A parent that changed its ids after its exec (`sudo`) names itself to the processes it makes by other ids than
    /// its exec gave it. The walk finds that exec by its pid and pid version, for a fork's child and its exec alike.
    ///
    /// - Throws: The error reading or storing the events, or an `XCTest` failure if a token is missing.
    func testParentWithChangedIDsIsFoundByImage() throws {
        let forked = try esloggerProcess(pid: 600, pidversion: 6000, path: "/bin/zsh", parent: (401, 4010))
        /// `sudo` as it forks, with group IDs 0, and as its exec made it, with 20.
        let sudo = try esloggerProcess(pid: 600, pidversion: 6001, path: "/usr/bin/sudo", parent: (401, 4010))
        var execed = sudo, token = try XCTUnwrap(sudo["audit_token"] as? [String: Any])
        (token["rgid"], token["egid"]) = (20, 20)
        execed["audit_token"] = token
        let child = try esloggerProcess(pid: 601, pidversion: 6010, path: "/usr/bin/sudo", parent: (600, 6001))
        let chmod = try esloggerProcess(pid: 601, pidversion: 6011, path: "/bin/chmod", parent: (600, 6001))
        var messages = [try shellExec(), try forkMessage(by: try shell(), of: forked),
                        try execMessage(by: forked, of: execed), try forkMessage(by: sudo, of: child),
                        try execMessage(by: child, of: chmod)]
        TraceLaunchedByParents().fill(&messages)
        try withEventStore(messages) { context, stored in
            let lookup = LineageLookup(context)
            XCTAssertNotEqual(stored[2].created_audit_token, stored[4].event.exec?.target.parent_audit_token_string)
            for event in [stored[3], stored[4]] {
                let steps = lookup.launchedByParents(of: event)
                XCTAssertEqual(steps.count, 3)
                assertStep(steps.first, .unixParent, pid: 600, event: stored[2], path: "/usr/bin/sudo")
                assertStep(steps.dropFirst().first, .unixParent, pid: 401, event: stored[0], path: "/bin/zsh")
            }
            XCTAssertEqual(lookup.parents(of: stored[4])?.unix.path, "/usr/bin/sudo")
        }
    }
    
    /// A process's creator is its exec when the store has one, else its fork, whatever their order, as
    /// `findParentProc` has always found it.
    ///
    /// - Throws: The error reading or storing the events.
    func testCreatorPrefersTheExec() throws {
        let child = try esloggerProcess(pid: 470, pidversion: 4700, path: "/bin/zsh", parent: (401, 4010))
        let before = try esloggerProcess(pid: 470, pidversion: 4699, path: "/bin/zsh", parent: (401, 4010))
        let events = [try forkMessage(by: try shell(), of: child), try execMessage(by: before, of: child)]
        try withEventStore(events) { context, stored in
            let token = try XCTUnwrap(stored[0].created_audit_token)
            XCTAssertEqual(token, stored[1].created_audit_token)
            XCTAssertEqual(try LineageLookup(context).creator(ofToken: token)?.objectID, stored[1].objectID)
            XCTAssertNil(try LineageLookup(context).creator(ofToken: ""))
        }
        try withEventStore([events[0]]) { context, stored in
            let token = try XCTUnwrap(stored[0].created_audit_token)
            XCTAssertEqual(try LineageLookup(context).creator(ofToken: token)?.objectID, stored[0].objectID)
        }
    }
}
