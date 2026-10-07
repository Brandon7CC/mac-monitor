//
//  CommandLineToolInstaller.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import OSLog
import SutroESFramework


// MARK: - Command line tool installer
/// Settings ▸ Command Line's state: what's at `/usr/local/bin/macmonitor`, and the change being made there.
///
/// Looking happens off the main thread since the signature check reads the tool. To make a change we ask an
/// administrator to approve it with the system's password prompt (``CommandLineToolAuthorization``). Then the Security
/// Extension makes the change as root. The plan comes from what Settings showed, so if the link changed in the
/// meantime nothing changes.
final class CommandLineToolInstaller: ObservableObject {
    /// What Settings shows, once we've looked
    @Published private(set) var inspection: CommandLineToolLink.Inspection?
    /// Is a change in progress?
    @Published private(set) var isChanging = false
    /// What went wrong with the last change, for an alert
    @Published var failure: String?

    /// The link for this copy of Mac Monitor
    private let link: CommandLineToolLink
    /// Logs what each change did
    private static let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "CommandLineTool")

    /// - Parameter link: The link for this copy of Mac Monitor.
    init(link: CommandLineToolLink = .forThisApp()) {
        self.link = link
    }

    /// Look again, off the main thread.
    func refresh() {
        let link = link
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let inspection = link.inspect()
            DispatchQueue.main.async { self?.inspection = inspection }
        }
    }

    /// Install, update or remove the link, then look again. Call on the main thread.
    ///
    /// - Parameters:
    ///   - action: What to do. Nothing happens unless Settings offers it right now.
    ///   - manager: Sends the change to the Security Extension.
    func perform(_ action: CommandLineToolLink.Action, through manager: EndpointSecurityManager) {
        guard !isChanging, let plan = inspection?.plan(action) else { return }
        isChanging = true
        /// The password prompt blocks, so we ask for approval off the main thread.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            switch CommandLineToolAuthorization.requestApproval(prompt: CommandLineToolAuthorization.prompt(for: plan)) {
            case .success(let approval):
                /// The reply holds on to the approval, so the authorization stays alive until the Security
                /// Extension has checked it.
                manager.changeCommandLineTool(plan, authorization: approval.externalForm) { outcome in
                    withExtendedLifetime(approval) { self?.finish(plan, outcome) }
                }
            case .failure(let outcome):
                DispatchQueue.main.async { self?.finish(plan, outcome) }
            }
        }
    }

    /// Report what a change did and look again. Call on the main thread.
    ///
    /// - Parameters:
    ///   - plan: The change.
    ///   - outcome: What happened.
    private func finish(_ plan: CommandLineToolLink.Plan, _ outcome: CommandLineToolLinker.Outcome) {
        Self.logger.log("""
            \(plan.action.rawValue, privacy: .public) \(plan.linkPath, privacy: .public): \
            \(String(describing: outcome), privacy: .public)
            """)
        isChanging = false
        failure = outcome.message(for: plan)
        refresh()
    }
}
