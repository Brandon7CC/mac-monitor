//
//  CommandLineToolAuthorization.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/6/26.
//

import Foundation
import Security


// MARK: - Command line tool authorization
/// The administrator approval behind Settings ▸ Command Line's Install… and Remove….
///
/// We use Authorization Services and our own right, ``rightName``:
///   - Mac Monitor asks for the right, which shows the system's password prompt. It sends the authorization's
///     external form to the Security Extension with the change.
///   - The Security Extension checks the same right on that authorization without any prompt, then makes the change as
///     root (``CommandLineToolLinker``).
///
/// We can't use `system.privilege.admin` because its rule allows root, so the Security Extension would pass the check
/// without anyone authenticating. Our rule (``rule``) never allows root and needs an administrator. The Security
/// Extension adds it to the authorization database at launch.
public enum CommandLineToolAuthorization {
    /// Our right in the authorization database
    public static let rightName = "com.swiftlydetecting.agent.command-line-tool"

    /// The rule for ``rightName``. An administrator has to authenticate, root gets no free pass, and the credentials
    /// last 30 seconds within this one authorization.
    static let rule: [String: Any] = [
        "class": "user", "group": "admin", "authenticate-user": true, "allow-root": false, "session-owner": false,
        "shared": false, "timeout": 30, "version": 1,
        "comment": "Installs or removes Mac Monitor's command line tool at /usr/local/bin/macmonitor."
    ]

    // MARK: Mac Monitor

    /// An administrator's approval of one change.
    ///
    /// The external form only works while the authorization behind it is alive. Keep the approval until the Security
    /// Extension replies. Releasing it frees the authorization and throws away its rights.
    public final class Approval {
        /// The authorization the administrator approved
        private let authorization: AuthorizationRef
        /// The authorization's external form for the Security Extension
        public let externalForm: Data

        /// - Parameters:
        ///   - authorization: The approved authorization. The approval frees it.
        ///   - externalForm: Its external form.
        init(_ authorization: AuthorizationRef, externalForm: Data) {
            self.authorization = authorization
            self.externalForm = externalForm
        }

        deinit {
            AuthorizationFree(authorization, [.destroyRights])
        }
    }

    /// Ask an administrator to approve a change. This blocks while the password prompt is up, so never call it on the
    /// main thread.
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

    /// What the password prompt says Mac Monitor wants to do.
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

    /// Add ``rightName`` to the authorization database if it isn't there yet. Only root may, so for anyone else this
    /// does nothing.
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

    /// Did an administrator approve this change? Never prompts.
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

    /// Call `body` with a rights set holding only ``rightName``.
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
