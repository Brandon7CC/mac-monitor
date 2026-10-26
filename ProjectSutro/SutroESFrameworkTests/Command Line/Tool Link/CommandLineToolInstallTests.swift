//
//  CommandLineToolInstallTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Approving and reporting a change
/// Tests outcome messages and the approval checks that don't need a password.
final class CommandLineToolInstallTests: XCTestCase {
    /// Outcomes survive their raw value, and all but done and cancelled have a message.
    func testEveryOutcomeIsReported() {
        let plan = CommandLineToolLink.Plan(action: .install, tool: "/A.app/Contents/MacOS/macmonitor",
                                            binDirectory: "/usr/local/bin", expected: "")
        for outcome in CommandLineToolLinker.Outcome.allCases {
            XCTAssertEqual(CommandLineToolLinker.Outcome(rawValue: outcome.rawValue), outcome)
            let message = outcome.message(for: plan)
            if outcome == .done || outcome == .cancelled {
                XCTAssertNil(message)
            } else {
                XCTAssertTrue(message?.contains("/usr/local/bin") == true || message?.contains(plan.tool) == true,
                              "\(outcome): \(message ?? "nil")")
            }
        }
    }

    /// The password prompt says what Mac Monitor is about to do: install, point the link at this copy, or remove.
    func testThePromptSaysWhatChanges() {
        let install = CommandLineToolLink.Plan(action: .install, tool: "/A.app/Contents/MacOS/macmonitor",
                                               binDirectory: "/usr/local/bin", expected: "")
        let update = CommandLineToolLink.Plan(action: .install, tool: install.tool, binDirectory: "/usr/local/bin",
                                              expected: "/B.app/Contents/MacOS/macmonitor")
        let remove = CommandLineToolLink.Plan(action: .remove, tool: "", binDirectory: "/usr/local/bin",
                                              expected: install.tool)
        XCTAssertEqual(CommandLineToolAuthorization.prompt(for: install),
                       "Mac Monitor wants to install its command line tool at /usr/local/bin/macmonitor.")
        XCTAssertEqual(CommandLineToolAuthorization.prompt(for: update),
                       "Mac Monitor wants to point /usr/local/bin/macmonitor at this copy of Mac Monitor.")
        XCTAssertEqual(CommandLineToolAuthorization.prompt(for: remove),
                       "Mac Monitor wants to remove its command line tool from /usr/local/bin/macmonitor.")
    }

    /// Our right never lets root through without an administrator, unlike `system.privilege.admin`.
    func testTheRuleNeedsAnAdministrator() {
        let rule = CommandLineToolAuthorization.rule
        XCTAssertEqual(rule["class"] as? String, "user")
        XCTAssertEqual(rule["allow-root"] as? Bool, false)
        XCTAssertEqual(rule["group"] as? String, "admin")
        XCTAssertEqual(rule["authenticate-user"] as? Bool, true)
        XCTAssertEqual(rule["session-owner"] as? Bool, false)
        XCTAssertEqual(rule["shared"] as? Bool, false)
        XCTAssertEqual(rule["timeout"] as? Int, 30)
    }
    
    /// The right as authd stores it after the Security Extension adds it, read with `security authorizationdb read`.
    private static let storedRule: [String: Any] = [
        "allow-root": false, "authenticate-user": true, "class": "user",
        "comment": "Installs or removes Mac Monitor's command line tool at /usr/local/bin/macmonitor.",
        "created": 813196884.489917, "group": "admin", "identifier": "com.swiftlydetecting.agent.securityextension",
        "modified": 813196884.489917, "requirement": "anchor apple generic", "session-owner": false, "shared": false,
        "timeout": 30, "tries": 10000, "version": 1
    ]
    
    /// The right authd stores is ours, but one a user added first with a weaker rule isn't, so it gets replaced.
    func testOnlyOurOwnRuleMatches() {
        XCTAssertTrue(CommandLineToolAuthorization.matches(Self.storedRule))
        XCTAssertTrue(CommandLineToolAuthorization.matches(CommandLineToolAuthorization.rule))
        let weaker: [String: [String: Any]] = [
            "anyone": ["class": "allow"],
            "a rule instead": ["class": "rule", "rule": ["allow"]],
            "root allowed": Self.storedRule.merging(["allow-root": true]) { $1 },
            "any user": Self.storedRule.merging(["group": "staff"]) { $1 },
            "no password": Self.storedRule.merging(["authenticate-user": false]) { $1 },
            "console user": Self.storedRule.merging(["session-owner": true]) { $1 },
            "shared": Self.storedRule.merging(["shared": true]) { $1 },
            "longer": Self.storedRule.merging(["timeout": 2147483647]) { $1 },
            "an extra key": Self.storedRule.merging(["entitled": true]) { $1 },
            "no group": Self.storedRule.filter { $0.key != "group" }
        ]
        for (name, stored) in weaker {
            XCTAssertFalse(CommandLineToolAuthorization.matches(stored), name)
        }
    }

    /// On a Mac where the Security Extension has run, the right read back through Authorization Services matches.
    /// This checks the values survive the trip from authd, which a dictionary literal can't.
    func testTheRegisteredRightMatches() throws {
        guard let stored = CommandLineToolAuthorization.storedRule() else {
            throw XCTSkip("The Security Extension hasn't registered its right on this Mac.")
        }
        XCTAssertTrue(CommandLineToolAuthorization.matches(stored), "\(stored)")
    }
    
    /// Anything that isn't an approved authorization's external form is refused.
    func testOnlyAnApprovedAuthorizationIsAccepted() throws {
        XCTAssertFalse(CommandLineToolAuthorization.isApproved(Data()))
        XCTAssertFalse(CommandLineToolAuthorization.isApproved(Data(repeating: 0, count: 31)))
        XCTAssertFalse(CommandLineToolAuthorization.isApproved(Data(repeating: 0, count: 32)))

        /// A real authorization nobody approved
        var authorization: AuthorizationRef?
        XCTAssertEqual(AuthorizationCreate(nil, nil, [], &authorization), errAuthorizationSuccess)
        let unapproved = try XCTUnwrap(authorization)
        defer { AuthorizationFree(unapproved, []) }
        var external = AuthorizationExternalForm()
        XCTAssertEqual(AuthorizationMakeExternalForm(unapproved, &external), errAuthorizationSuccess)
        XCTAssertFalse(CommandLineToolAuthorization.isApproved(withUnsafeBytes(of: &external) { Data($0) }))
    }
}
