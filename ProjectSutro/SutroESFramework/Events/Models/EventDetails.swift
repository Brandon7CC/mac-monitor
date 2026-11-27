//
//  EventDetails.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Event details
/// What Event Facts' Details box shows: a network flow's identifier and when it opened, then a tab each for audit
/// tokens, and an exec's environment, code signing flags and file descriptors. A tab with nothing to show is left out.
public struct EventDetails {
    /// A tab, titled by its raw value. The cases are in the order the box shows them.
    public enum Tab: String, CaseIterable, Identifiable {
        case environment = "Environment"
        case auditTokens = "Audit tokens"
        case codeSigningFlags = "Code signing flags"
        case fileDescriptors = "File descriptors"

        public var id: Self { self }
    }

    /// An audit token and its fact's name.
    public struct AuditToken: Identifiable {
        /// The fact's name, such as "Target parent audit token".
        public let name: String
        /// The token.
        public let token: String

        public var id: String { name }
    }

    /// An exec's environment variables.
    public private(set) var environment: [EnvironmentVariable] = []
    /// The audit tokens of the process that made the event, then those of the process it acted on.
    public private(set) var auditTokens: [AuditToken] = []
    /// The flags set in an exec's code signing flags.
    public private(set) var codeSigningFlags: [CodeSigningFlag] = []
    /// An exec's file descriptors.
    public private(set) var fileDescriptors: [FileDescriptor] = []

    /// The facts above the tabs: a network flow's identifier and when its socket was made (``NetworkFlowFacts``).
    public private(set) var facts: [EventFact] = []

    /// Is there nothing to show, no facts and no tabs?
    public var isEmpty: Bool { facts.isEmpty && tabs.isEmpty }

    /// The tabs with anything to show, in order.
    public var tabs: [Tab] { Tab.allCases.filter { count(of: $0) > 0 } }

    /// - Parameter tab: The tab.
    /// - Returns: How many items it shows.
    public func count(of tab: Tab) -> Int {
        switch tab {
        case .environment: environment.count
        case .auditTokens: auditTokens.count
        case .codeSigningFlags: codeSigningFlags.count
        case .fileDescriptors: fileDescriptors.count
        }
    }

    /// The tab the box shows: the one picked last when this event has it, or else its first.
    ///
    /// - Parameter picked: The tab picked last, or `nil` before one is picked.
    /// - Returns: The tab, or `nil` when there are no tabs.
    public func shownTab(picked: Tab?) -> Tab? {
        let tabs = tabs
        return picked.flatMap { tabs.contains($0) ? $0 : nil } ?? tabs.first
    }
}


// MARK: - From an event
extension EventDetails {
    /// The names of a process's own, responsible and parent audit tokens.
    private static let processTokenNames = ["Process audit token", "Responsible audit token", "Parent audit token"]
    /// The same names for the process an event acted on.
    private static let targetTokenNames = ["Target audit token", "Target responsible audit token",
                                           "Target parent audit token"]

    /// A process's audit tokens alone, as the Parent tab shows them.
    ///
    /// - Parameter process: The process.
    public init(process: ESProcess) {
        auditTokens = Self.auditTokens(of: process, names: Self.processTokenNames)
    }

    /// An event's details in the Metadata tab: a network flow's identifier and when it opened, the audit tokens of the
    /// process that made it and of the process it acted on, and an exec's environment, code signing flags and file
    /// descriptors.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - target: The process it acted on, or `nil` without one.
    public init(message: ESMessage, target: ESProcess?) {
        self.init(process: message.process)
        if let target {
            auditTokens += Self.auditTokens(of: target, names: Self.targetTokenNames)
        }
        if let exec = message.event.exec {
            environment = EnvironmentVariable.variables(in: exec.env)
            codeSigningFlags = ProcessHelpers.codeSigningFlags(exec.target.codesigning_flags)
            fileDescriptors = exec.fds
        }
        facts = NetworkFlowFacts(message: message)?.details ?? []
    }

    /// - Parameters:
    ///   - process: The process.
    ///   - names: The names of its own, responsible and parent audit tokens.
    /// - Returns: The tokens it has, each with its name.
    private static func auditTokens(of process: ESProcess, names: [String]) -> [AuditToken] {
        let tokens = [process.audit_token_string, process.responsible_audit_token_string,
                      process.parent_audit_token_string]
        return zip(names, tokens).filter { !$0.1.isEmpty }.map { AuditToken(name: $0.0, token: $0.1) }
    }
}
