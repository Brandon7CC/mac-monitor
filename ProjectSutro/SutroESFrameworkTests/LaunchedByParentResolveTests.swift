//
//  LaunchedByParentResolveTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Resolving a launched-by parent
/// Pins the order in which a message's own fields name a created process's launched-by parent: one case per shape of
/// launch (a shell's child, an adopted process, an XPC service, a launchd job, an app, `xpcproxy`).
final class LaunchedByParentResolveTests: XCTestCase {
    /// launchd.
    private let launchd = AuditToken.fixture(pid: 1, pidversion: 1)
    /// A shell, and the process it started (and its later image).
    private let shell = AuditToken.fixture(pid: 401, pidversion: 4010)
    /// The terminal app the shell runs in.
    private let terminal = AuditToken.fixture(pid: 300, pidversion: 3000)
    
    /// A launchd child's lineage: launchd's token and pid, and `ppid` and `original_ppid` 1.
    ///
    /// - Parameters:
    ///   - pid: The child's pid.
    ///   - responsible: Its responsible process's token, by default its own.
    ///   - env: Its exec environment.
    ///   - byXPCProxy: Did `xpcproxy` exec it? By default it did, as it does a job's program.
    /// - Returns: The lineage.
    private func launchdChild(_ pid: Int32, responsible: AuditToken? = nil, env: [String],
                              byXPCProxy: Bool = true) -> LaunchedByParent.Lineage {
        LaunchedByParent.Lineage(pid: pid, ppid: 1, original_ppid: 1, parent_audit_token: launchd,
                                 responsible_audit_token: responsible ?? .fixture(pid: pid, pidversion: 9),
                                 by: .exec(env: env, byXPCProxy: byXPCProxy))
    }
    
    /// Resolve as the Security Extension does, naming a process's executable `/path/of/<pid>`.
    ///
    /// - Parameter lineage: The lineage.
    /// - Returns: The launched-by parent.
    private func resolve(_ lineage: LaunchedByParent.Lineage) -> LaunchedByParent {
        LaunchedByParent.resolve(lineage, by: .securityExtension) { pid, _ in "/path/of/\(pid)" }
    }
    
    /// Resolve with a `path` that fails the test if it's called.
    ///
    /// - Parameters:
    ///   - lineage: The lineage.
    ///   - line: The caller's line, for the failure.
    /// - Returns: The launched-by parent.
    private func resolveWithoutPaths(_ lineage: LaunchedByParent.Lineage, line: UInt = #line) -> LaunchedByParent {
        LaunchedByParent.resolve(lineage, by: .securityExtension) { pid, _ in
            XCTFail("Read the path of \(pid)", line: line)
            return nil
        }
    }
    
    /// A shell's child: its Unix parent, by token, with the path read by pid.
    func testShellChildIsUnixParent() {
        let answer = resolve(.init(pid: 402, ppid: 401, original_ppid: 401, parent_audit_token: shell,
                                   responsible_audit_token: terminal,
                                   by: .exec(env: ["XPC_SERVICE_NAME=0"], byXPCProxy: false)))
        XCTAssertEqual(answer, LaunchedByParent(source: .unixParent, audit_token: shell, path: "/path/of/401",
                                                resolved_by: .securityExtension))
        XCTAssertEqual(answer.pid, 401)
        XCTAssertNil(answer.launchd_job)
    }
    
    /// Without a parent token, `ppid` names the Unix parent.
    func testWithoutParentTokenUsesPPID() {
        let answer = resolve(.init(pid: 402, ppid: 401, original_ppid: 401, parent_audit_token: nil,
                                   responsible_audit_token: nil, by: .exec(env: [], byXPCProxy: false)))
        XCTAssertEqual(answer.source, .unixParent)
        XCTAssertEqual(answer.pid, 401)
        XCTAssertNil(answer.audit_token)
        XCTAssertEqual(answer.path, "/path/of/401")
    }
    
    /// A process launchd adopted before its exec (`nohup` in a shell that exited): its original parent, by pid only,
    /// without the label it inherited and without reading a path.
    func testAdoptedProcessIsOriginalParentByPIDOnly() {
        let answer = resolveWithoutPaths(.init(pid: 430, ppid: 1, original_ppid: 401, parent_audit_token: launchd,
                                               responsible_audit_token: terminal,
                                               by: .exec(env: ["XPC_SERVICE_NAME=com.example.agent"],
                                                         byXPCProxy: false)))
        XCTAssertEqual(answer, LaunchedByParent(source: .unixParent, audit_token: nil, pid: 401, path: nil,
                                                resolved_by: .securityExtension))
    }
    
    /// An XPC service: launchd's child, with its host app responsible. Its job's label rides along.
    func testXPCServiceIsResponsibleProcessWithLabel() {
        let host = AuditToken.fixture(pid: 500, pidversion: 5000)
        let answer = resolve(launchdChild(420, responsible: host, env: ["XPC_SERVICE_NAME=com.example.App.Service"]))
        XCTAssertEqual(answer, LaunchedByParent(source: .responsibleProcess, audit_token: host, path: "/path/of/500",
                                                launchd_job: .init(label: "com.example.App.Service"),
                                                resolved_by: .securityExtension))
    }
    
    /// A launchd job is its own responsible process: launchd, with the job's label.
    func testLaunchdJobByLabel() {
        let env = ["PATH=/usr/bin", "XPC_SERVICE_NAME=com.example.agent"]
        let answer = resolveWithoutPaths(launchdChild(410, env: env))
        XCTAssertEqual(answer, LaunchedByParent(source: .launchdJob, audit_token: launchd,
                                                path: LaunchedByParent.launchdPath,
                                                launchd_job: .init(label: "com.example.agent"),
                                                resolved_by: .securityExtension))
        XCTAssertEqual(answer.pid, 1)
        XCTAssertFalse(answer.needsLaunchServices)
    }
    
    /// An app LaunchServices launched is a launchd job until Mac Monitor asks LaunchServices: any answer but the Unix
    /// parent with an app instance's label needs it.
    func testAppIsLaunchdJobThatNeedsLaunchServices() {
        let label = Self.lineageAppLabel
        let answer = resolve(launchdChild(500, env: ["XPC_SERVICE_NAME=\(label)"]))
        XCTAssertEqual(answer.source, .launchdJob)
        XCTAssertEqual(answer.launchd_job?.label, label)
        XCTAssertTrue(answer.needsLaunchServices)
        
        let job = LaunchedByParent.LaunchdJob(label: label)
        XCTAssertTrue(LaunchedByParent(source: .responsibleProcess, audit_token: terminal, path: nil, launchd_job: job,
                                       resolved_by: .securityExtension).needsLaunchServices)
        XCTAssertFalse(LaunchedByParent(source: .unixParent, audit_token: launchd, path: nil, launchd_job: job,
                                        resolved_by: .securityExtension).needsLaunchServices)
    }
    
    /// A job's program that execs again, with whatever label it likes, is still launchd's child, but its new image
    /// names no job: only `xpcproxy` sets the label of the job it starts. An XPC service's re-exec keeps its host.
    func testReexecNamesNoJob() {
        for label in ["com.apple.softwareupdated", Self.lineageAppLabel] {
            let answer = resolveWithoutPaths(launchdChild(410, env: ["XPC_SERVICE_NAME=\(label)"], byXPCProxy: false))
            XCTAssertEqual(answer, LaunchedByParent(source: .unixParent, audit_token: launchd,
                                                    path: LaunchedByParent.launchdPath,
                                                    resolved_by: .securityExtension), label)
            XCTAssertFalse(answer.needsLaunchServices, label)
        }
        let host = AuditToken.fixture(pid: 500, pidversion: 5000)
        let service = resolve(launchdChild(420, responsible: host, env: ["XPC_SERVICE_NAME=com.example.App.Service"],
                                           byXPCProxy: false))
        XCTAssertEqual(service.source, .responsibleProcess)
        XCTAssertEqual(service.audit_token, host)
        XCTAssertNil(service.launchd_job)
    }
    
    /// `xpcproxy`, exec'd by launchd's fork before it knows the job: nothing better than launchd.
    func testXPCProxyIsLaunchd() {
        let answer = resolveWithoutPaths(launchdChild(410, env: [], byXPCProxy: false))
        XCTAssertEqual(answer, LaunchedByParent(source: .unixParent, audit_token: launchd,
                                                path: LaunchedByParent.launchdPath, resolved_by: .securityExtension))
        XCTAssertTrue(answer.isLaunchd)
    }
    
    /// launchd's `0` for a process that isn't a job, and an empty label, name no job.
    func testZeroAndEmptyLabelsAreNone() {
        for env in [["XPC_SERVICE_NAME=0"], ["XPC_SERVICE_NAME="]] {
            let answer = resolveWithoutPaths(launchdChild(440, env: env))
            XCTAssertEqual(answer.source, .unixParent, "\(env)")
            XCTAssertNil(answer.launchd_job, "\(env)")
        }
    }
    
    /// A label is only trusted on a direct launchd child: a job's own child inherited it.
    func testInheritedLabelIsIgnored() {
        let job = AuditToken.fixture(pid: 410, pidversion: 4102)
        let answer = resolve(.init(pid: 451, ppid: 410, original_ppid: 410, parent_audit_token: job,
                                   responsible_audit_token: job,
                                   by: .exec(env: ["XPC_SERVICE_NAME=com.example.agent"], byXPCProxy: false)))
        XCTAssertEqual(answer.source, .unixParent)
        XCTAssertEqual(answer.audit_token, job)
        XCTAssertNil(answer.launchd_job)
    }
    
    /// A responsible process that's the process itself (a launchd job, an app) or launchd names nothing.
    func testResponsibleSelfOrLaunchdIsIgnored() {
        for responsible in [AuditToken.fixture(pid: 410, pidversion: 4101), launchd] {
            let answer = resolveWithoutPaths(launchdChild(410, responsible: responsible, env: []))
            XCTAssertEqual(answer.source, .unixParent, "\(responsible.pid)")
            XCTAssertEqual(answer.pid, 1)
        }
    }
    
    /// A fork names its parent from the forking process's executable, never by reading a path.
    func testForkNamesParentFromForkingProcess() {
        let child = LaunchedByParent.Lineage(pid: 402, ppid: 401, original_ppid: 401, parent_audit_token: shell,
                                             responsible_audit_token: terminal, by: .fork(parentPath: "/bin/zsh"))
        XCTAssertEqual(resolveWithoutPaths(child), LaunchedByParent(source: .unixParent, audit_token: shell,
                                                                    path: "/bin/zsh", resolved_by: .securityExtension))
        let unnamed = LaunchedByParent.Lineage(pid: 402, ppid: 401, original_ppid: 401, parent_audit_token: shell,
                                               responsible_audit_token: terminal, by: .fork(parentPath: nil))
        XCTAssertNil(resolveWithoutPaths(unnamed).path)
        let launchdFork = LaunchedByParent.Lineage(pid: 410, ppid: 1, original_ppid: 1, parent_audit_token: launchd,
                                                   responsible_audit_token: .fixture(pid: 410, pidversion: 4100),
                                                   by: .fork(parentPath: LaunchedByParent.launchdPath))
        XCTAssertEqual(resolveWithoutPaths(launchdFork).path, LaunchedByParent.launchdPath)
    }
    
    /// Live paths: launchd's and this process's executables, and nothing for pid 0 or a negative pid.
    func testLivePaths() {
        XCTAssertEqual(ProcessPath.of(1), LaunchedByParent.launchdPath)
        let ownPath = ProcessPath.live(getpid(), nil).map { URL(fileURLWithPath: $0).resolvingSymlinksInPath() }
        let executable = Bundle.main.executableURL?.resolvingSymlinksInPath()
        XCTAssertNotNil(ownPath)
        XCTAssertEqual(ownPath, executable)
        XCTAssertNil(ProcessPath.of(0))
        XCTAssertNil(ProcessPath.of(-1))
    }
}
