//
//  LaunchedByParentLaunchServicesTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Upgrading with LaunchServices
/// Pins when Mac Monitor takes LaunchServices' record of an app's launch, and what it makes of the Security
/// Extension's answer: the launcher, no launcher recorded, or the answer kept.
final class LaunchedByParentLaunchServicesTests: XCTestCase {
    /// An app's label, as launchd names a LaunchServices instance.
    private let label = XCTestCase.lineageAppLabel
    /// The app, as its exec names it.
    private let app = AuditToken.fixture(pid: 501, pidversion: 5010)
    /// The process that asked LaunchServices to launch it.
    private let launcher = AuditToken.fixture(pid: 502, pidversion: 5020)
    
    /// The Security Extension's answer for the app: launchd, starting the app's job.
    private var appJob: LaunchedByParent {
        LaunchedByParent(source: .launchdJob, audit_token: .fixture(pid: 1, pidversion: 1),
                         path: LaunchedByParent.launchdPath, launchd_job: .init(label: label),
                         resolved_by: .securityExtension)
    }
    
    /// A record of the app's launch.
    ///
    /// - Parameters:
    ///   - token: The process that checked in, by default the app.
    ///   - launched: Did LaunchServices launch it?
    ///   - parentASN: Does the record name a launcher?
    ///   - parent: The launcher, when LaunchServices can still read it.
    /// - Returns: The record.
    private func record(of token: AuditToken? = nil, launched: Bool = true, parentASN: Bool,
                        parent: AuditToken?) -> LaunchServicesRecord {
        LaunchServicesRecord(token: token ?? app, launchedByLaunchServices: launched, hasParentASN: parentASN,
                             parentToken: parent)
    }
    
    /// Upgrade an answer, naming the launcher `/path/of/<pid>`.
    ///
    /// - Parameters:
    ///   - answer: The answer.
    ///   - record: LaunchServices' record.
    /// - Returns: The upgraded answer, or `nil`.
    private func upgrade(_ answer: LaunchedByParent, with record: LaunchServicesRecord) -> LaunchedByParent? {
        answer.upgraded(with: record, for: app) { pid, _ in "/path/of/\(pid)" }
    }
    
    /// We get the launcher Launch Services recorded, with its token and path. The app's label is kept and the Security
    /// Extension is credited. Only answers that need Launch Services are upgraded, not the Unix parent.
    ///
    /// - Throws: An `XCTest` failure if the launcher's answer is missing.
    func testOnlyAnswersThatNeedLaunchServicesAreUpgraded() throws {
        let launched = record(parentASN: true, parent: launcher)
        let answer = try XCTUnwrap(upgrade(appJob, with: launched))
        XCTAssertEqual(answer, LaunchedByParent(source: .launchServices, audit_token: launcher, path: "/path/of/502",
                                                launchd_job: .init(label: label), resolved_by: .securityExtension))
        XCTAssertEqual(answer.pid, 502)
        
        var responsible = appJob
        responsible.source = .responsibleProcess
        XCTAssertEqual(upgrade(responsible, with: launched), answer)
        
        var unixParent = appJob
        unixParent.source = .unixParent
        XCTAssertNil(upgrade(unixParent, with: launched))
        var agent = appJob
        agent.launchd_job = .init(label: "com.example.agent")
        XCTAssertNil(upgrade(agent, with: launched))
    }
    
    /// A record of another exec of the app's pid (a reused pid, or an exec after the app checked in) is ignored.
    func testRecordOfAnotherExecIsIgnored() {
        let reused = AuditToken.fixture(pid: 501, pidversion: 5011)
        XCTAssertNil(upgrade(appJob, with: record(of: reused, parentASN: true, parent: launcher)))
        XCTAssertNil(upgrade(appJob, with: record(of: reused, parentASN: false, parent: nil)))
    }
    
    /// The launcher's path comes from its own record when that holds one: the launcher may have quit, and another
    /// process may have its pid. Without one, it's read by pid.
    ///
    /// - Throws: An `XCTest` failure if the launcher's answer is missing.
    func testLauncherPathFromItsRecord() throws {
        let path = "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"
        let launched = LaunchServicesRecord(token: app, launchedByLaunchServices: true, hasParentASN: true,
                                            parentToken: launcher, parentPath: path)
        let answer = try XCTUnwrap(appJob.upgraded(with: launched, for: app) { pid, _ in
            XCTFail("Read the path of \(pid)")
            return nil
        })
        XCTAssertEqual(answer.path, path)
        XCTAssertEqual(answer.audit_token, launcher)
        XCTAssertEqual(upgrade(appJob, with: record(parentASN: true, parent: launcher))?.path, "/path/of/502")
    }
    
    /// A record that names the app as its own launcher is ignored.
    func testLauncherThatIsTheAppIsIgnored() {
        XCTAssertNil(upgrade(appJob, with: record(parentASN: true, parent: app)))
    }
    
    /// `open` from a shell: LaunchServices launched the app and recorded no launcher. The launchd job becomes a
    /// LaunchServices launch without a process, keeping the label; a responsible process stays.
    ///
    /// - Throws: An `XCTest` failure if the answer is missing.
    func testLaunchWithoutLauncher() throws {
        let answer = try XCTUnwrap(upgrade(appJob, with: record(parentASN: false, parent: nil)))
        XCTAssertEqual(answer, LaunchedByParent(source: .launchServices, audit_token: nil, pid: nil, path: nil,
                                                launchd_job: .init(label: label), resolved_by: .securityExtension))
        
        var responsible = appJob
        responsible.source = .responsibleProcess
        XCTAssertNil(upgrade(responsible, with: record(parentASN: false, parent: nil)))
        XCTAssertNil(upgrade(appJob, with: record(launched: false, parentASN: false, parent: nil)))
    }
    
    /// A launcher LaunchServices has forgotten (it quit) leaves the answer as it was, rather than claiming no launcher
    /// was recorded.
    func testForgottenLauncherKeepsTheAnswer() {
        XCTAssertNil(upgrade(appJob, with: record(parentASN: true, parent: nil)))
    }
    
    /// `LSAuditToken` is `audit_token_t`'s 32 bytes: read with a zeroed `id`, any other size refused.
    ///
    /// - Throws: An `XCTest` failure if the token isn't read.
    func testAuditTokenData() throws {
        let raw = RawMessageFixture.auditToken(pid: 501, euid: 501, pidversion: 5010, asid: 100_002)
        let data = withUnsafeBytes(of: raw) { Data($0) }
        let token = try XCTUnwrap(AuditToken(auditTokenData: data))
        XCTAssertEqual(token, AuditToken(from: raw).rowKey)
        XCTAssertEqual(token.pid, 501)
        XCTAssertEqual(token.pidversion, 5010)
        XCTAssertEqual(token.asid, 100_002)
        XCTAssertEqual(token.euid, 501)
        
        XCTAssertNil(AuditToken(auditTokenData: data.dropLast()))
        XCTAssertNil(AuditToken(auditTokenData: data + Data([0])))
        XCTAssertNil(AuditToken(auditTokenData: Data()))
    }
}
