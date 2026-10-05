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
/// Looking happens off the main thread, since the signature check reads the tool. A change runs
/// ``CommandLineToolLinkScript`` as root behind the administrator password prompt, on the main thread as
/// `NSAppleScript` requires. Its plan comes from what Settings showed, so if the link changed meanwhile the script
/// changes nothing.
final class CommandLineToolInstaller: ObservableObject {
    /// What Settings shows, once looked at.
    @Published private(set) var inspection: CommandLineToolLink.Inspection?
    /// Is a change waiting on the password prompt?
    @Published private(set) var isChanging = false
    /// What went wrong with the last change, for an alert.
    @Published var failure: String?
    
    /// The link for this copy of Mac Monitor.
    private let link: CommandLineToolLink
    /// Logs what each change did.
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
    
    /// Install, update or remove the link behind the password prompt, then look again. Call on the main thread.
    ///
    /// - Parameter action: What to do. Nothing happens unless Settings offers it right now.
    func perform(_ action: CommandLineToolLink.Action) {
        guard !isChanging, let plan = inspection?.plan(action) else { return }
        isChanging = true
        /// Let Settings show the change in progress before the prompt holds the main thread.
        DispatchQueue.main.async { [self] in
            let outcome = CommandLineToolLinkScript.run(plan)
            Self.logger.log("""
                \(plan.action.rawValue, privacy: .public) \(plan.linkPath, privacy: .public): \
                \(String(describing: outcome), privacy: .public)
                """)
            isChanging = false
            failure = outcome.message(for: plan)
            refresh()
        }
    }
}
