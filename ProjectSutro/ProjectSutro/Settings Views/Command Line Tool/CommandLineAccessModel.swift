//
//  CommandLineAccessModel.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation
import OSLog
import SutroESFramework


// MARK: - Command line access model
/// Settings ▸ Command Line ▸ Without sudo's state: who may use `macmonitor` without `sudo`, as the Security
/// Extension stores it, and the change being made.
///
/// The Security Extension decides whether this Mac Monitor may change it (while it owns the event stream or nobody
/// does) and keeps the result, so Settings shows what it replies.
final class CommandLineAccessModel: ObservableObject {
    /// The level, or `nil` until the Security Extension answers (or if it can't be reached).
    @Published private(set) var access: CommandLineAccess?
    @Published private(set) var isChanging = false
    /// Shown in an alert
    @Published var failure: String?

    private static let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "CommandLineAccess")

    /// Ask the Security Extension again. Call on the main thread.
    ///
    /// - Parameter manager: Asks the Security Extension.
    func refresh(through manager: EndpointSecurityManager) {
        manager.commandLineAccess { [weak self] in self?.access = $0 }
    }

    /// Change the level, then ask again. Call on the main thread.
    ///
    /// - Parameters:
    ///   - access: The new level.
    ///   - manager: Sends the change to the Security Extension.
    func change(to access: CommandLineAccess, through manager: EndpointSecurityManager) {
        guard !isChanging, let current = self.access, access != current else { return }
        isChanging = true
        manager.setCommandLineAccess(access) { [weak self] outcome in
            Self.logger.log("\(access.rawValue, privacy: .public): \(String(describing: outcome), privacy: .public)")
            self?.isChanging = false
            self?.failure = outcome.message
            self?.refresh(through: manager)
        }
    }
}
