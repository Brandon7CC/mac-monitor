//
//  CommandLineToolAuthorization.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/6/26.
//

import Foundation
import Security


// MARK: - Command line tool authorization
/// Administrator approval for Settings ▸ Command Line.
///
/// Mac Monitor asks for ``rightName`` (the password prompt) and sends the external form to the Security Extension,
/// which checks the same right before making the change. We don't use `system.privilege.admin` since it allows root.
public enum CommandLineToolAuthorization {
    public static let rightName = "com.swiftlydetecting.agent.command-line-tool"

    /// Admin only, never root, valid for 30 seconds
    static let rule: [String: Any] = [
        "class": "user", "group": "admin", "authenticate-user": true, "allow-root": false, "session-owner": false,
        "shared": false, "timeout": 30, "version": 1,
        "comment": "Installs or removes Mac Monitor's command line tool at /usr/local/bin/macmonitor."
    ]

    // MARK: Mac Monitor

    /// An approved authorization. Keep it until the Security Extension replies, since the external form stops working
    /// once it's freed.
    public final class Approval {
        private let authorization: AuthorizationRef
        public let externalForm: Data

        /// - Parameters:
        ///   - authorization: The approved authorization. Freed on deinit.
        ///   - externalForm: Its external form.
        init(_ authorization: AuthorizationRef, externalForm: Data) {
            self.authorization = authorization
            self.externalForm = externalForm
        }

        deinit {
            AuthorizationFree(authorization, [.destroyRights])
        }
    }

    /// Show the password prompt. Blocks, so don't call it on the main thread.
    ///
    /// - Parameter prompt: What the prompt says Mac Monitor wants to do.
    /// - Returns: The approval, or the outcome to report (cancelled or not authorized).
    public static func requestApproval(prompt: String) -> Result<Approval, CommandLineToolLinker.Outcome> {
        var created: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &created) == errAuthorizationSuccess,
              let authorization = created else { return .failure(.notAuthorized) }

        let status = prompt.withCString { promptText in
            withRights { rights in
                var item = AuthorizationItem(name: kAuthorizationEnvironmentPrompt, valueLength: strlen(promptText),
                                             value: UnsafeMutableRawPointer(mutating: promptText), flags: 0)
                return withUnsafeMutablePointer(to: &item) { item in
                    var environment = AuthorizationEnvironment(count: 1, items: item)
                    return AuthorizationCopyRights(authorization, rights, &environment,
                                                   [.interactionAllowed, .extendRights, .preAuthorize], nil)
                }
            }
        }
        var external = AuthorizationExternalForm()
        guard status == errAuthorizationSuccess,
              AuthorizationMakeExternalForm(authorization, &external) == errAuthorizationSuccess else {
            AuthorizationFree(authorization, [.destroyRights])
            return .failure(status == errAuthorizationCanceled ? .cancelled : .notAuthorized)
        }
        return .success(Approval(authorization, externalForm: withUnsafeBytes(of: &external) { Data($0) }))
    }

    /// The password prompt's text.
    ///
    /// - Parameter plan: The plan.
    /// - Returns: A sentence.
    public static func prompt(for plan: CommandLineToolLink.Plan) -> String {
        let link = plan.linkPath
        switch plan.action {
        case .install where plan.expected.isEmpty:
            return "Mac Monitor wants to install its command line tool at \(link)."
        case .install:
            return "Mac Monitor wants to point \(link) at this copy of Mac Monitor."
        case .remove:
            return "Mac Monitor wants to remove its command line tool from \(link)."
        }
    }

    // MARK: Security Extension

    /// Add ``rightName`` to the authorization database if it's missing. Root only.
    ///
    /// - Returns: The status from Authorization Services.
    @discardableResult
    public static func registerRight() -> OSStatus {
        guard geteuid() == 0 else { return errAuthorizationDenied }
        guard AuthorizationRightGet(rightName, nil) != errAuthorizationSuccess else { return errAuthorizationSuccess }
        var authorization: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &authorization) == errAuthorizationSuccess,
              let authorization else { return errAuthorizationInternal }
        defer { AuthorizationFree(authorization, []) }
        return AuthorizationRightSet(authorization, rightName, rule as CFDictionary, nil, nil, nil)
    }

    /// Did an administrator approve this? Never prompts.
    ///
    /// - Parameter externalForm: The external form Mac Monitor sent.
    /// - Returns: `true` if the authorization holds ``rightName``.
    public static func isApproved(_ externalForm: Data) -> Bool {
        guard externalForm.count == MemoryLayout<AuthorizationExternalForm>.size else { return false }
        registerRight()
        var external = AuthorizationExternalForm()
        _ = withUnsafeMutableBytes(of: &external) { externalForm.copyBytes(to: $0) }
        var authorization: AuthorizationRef?
        guard AuthorizationCreateFromExternalForm(&external, &authorization) == errAuthorizationSuccess,
              let authorization else { return false }
        defer { AuthorizationFree(authorization, []) }
        return withRights { AuthorizationCopyRights(authorization, $0, nil, [.extendRights], nil) }
            == errAuthorizationSuccess
    }

    /// Call `body` with a rights set of just ``rightName``.
    ///
    /// - Parameter body: Uses the rights.
    /// - Returns: What `body` returns.
    private static func withRights(_ body: (UnsafePointer<AuthorizationRights>) -> OSStatus) -> OSStatus {
        rightName.withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { item in
                var rights = AuthorizationRights(count: 1, items: item)
                return body(&rights)
            }
        }
    }
}
