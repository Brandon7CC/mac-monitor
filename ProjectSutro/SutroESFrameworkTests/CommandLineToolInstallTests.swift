//
//  CommandLineToolInstallTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Approving and reporting a change
/// Tests what Settings tells the user about a change, and the parts of the administrator approval we can check
/// without a password. The VM covers the real prompt.
final class CommandLineToolInstallTests: XCTestCase {
    /// Every outcome travels over XPC as its raw value. Every outcome but done and cancelled tells the user something
    /// about the link.
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
        XCTAssertEqual(rule["allow-root"] as? Bool, false)
        XCTAssertEqual(rule["group"] as? String, "admin")
        XCTAssertEqual(rule["authenticate-user"] as? Bool, true)
        XCTAssertEqual(rule["shared"] as? Bool, false)
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
