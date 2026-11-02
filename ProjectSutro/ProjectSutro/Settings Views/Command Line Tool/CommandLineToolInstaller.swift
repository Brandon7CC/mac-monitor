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
/// An administrator approves each change (``CommandLineToolAuthorization``), then the Security Extension makes it.
final class CommandLineToolInstaller: ObservableObject {
    @Published private(set) var inspection: CommandLineToolLink.Inspection?
    @Published private(set) var isChanging = false
    /// Shown in an alert
    @Published var failure: String?

    private let link: CommandLineToolLink
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
    ///   - action: What to do, if Settings offers it.
    ///   - manager: Sends the change to the Security Extension.
    func perform(_ action: CommandLineToolLink.Action, through manager: EndpointSecurityManager) {
        guard !isChanging, let plan = inspection?.plan(action) else { return }
        isChanging = true
        // The password prompt blocks.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let prompt = CommandLineToolAuthorization.prompt(for: plan)
            switch CommandLineToolAuthorization.requestApproval(prompt: prompt) {
            case .success(let approval):
                // Keep the authorization alive until the Security Extension has checked it.
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
