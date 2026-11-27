//
//  XProtectRuleStatus.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/26/26.
//

import Foundation


// MARK: - Are the rules loaded
/// Whether the XProtect rules Mac Monitor's capture scans written files with are compiled and loaded in the Security
/// Extension, for Settings > XProtect Rules. The Security Extension answers from what it holds, and never loads rules
/// to answer.
public struct XProtectRuleStatus: Codable, Equatable, Sendable {
    /// Where the rules stand.
    public enum State: String, Codable, Sendable {
        /// Scanning written files is off.
        case off
        /// Scanning is on, and the rules load once capture subscribes to Close or Exec events.
        case waiting
        /// Capture scans, and the rules load with the next file it scans. On macOS 13 they go after a quiet minute.
        case unloaded
        /// The rules are compiled and loaded.
        case loaded
        /// No rule file could be loaded.
        case failed
    }

    /// Where the rules stand now.
    public var state: State
    /// The XProtect version of the rules loaded, or `nil` while none are.
    public var version: String?
    /// Why each rule file that didn't load couldn't be, as sentences.
    public var problems: [String] = []

    /// What Settings says after the XProtect version and the rule count.
    ///
    /// - Parameter listed: The XProtect version Settings lists.
    /// - Returns: Such as "compiled and loaded", with the loaded version first when it's another. Rules loaded while
    ///   a rule file didn't load are "partly loaded".
    public func summary(listing listed: String) -> String {
        let loaded = version.map { $0 == listed ? "" : "XProtect \($0) " } ?? ""
        switch state {
        case .off: return "scanning is off"
        case .waiting: return "loads once Close or Exec events are captured"
        case .unloaded: return "loads when a file is scanned"
        case .loaded: return loaded + (problems.isEmpty ? "compiled and loaded" : "partly loaded")
        case .failed: return "didn't load"
        }
    }

    /// The status as the Security Extension sends it.
    var encoded: Data { (try? JSONEncoder().encode(self)) ?? Data() }
}


// MARK: - Asking the Security Extension
extension EndpointSecurityManager {
    /// Ask the Security Extension whether the XProtect rules capture scans written files with are loaded. Any caller
    /// may ask, so it goes on a connection of its own (``SensorClient/probe(caller:_:completion:)``): a Security
    /// Extension older than 3.3.0 closes the connection that asks, which mustn't be the one that owns the event
    /// stream.
    ///
    /// - Parameter completion: Called on the main thread with the status, or `nil` if the Security Extension couldn't
    ///   be reached or doesn't know the call.
    public func xprotectRuleStatus(completion: @escaping (XProtectRuleStatus?) -> Void) {
        sensor.probe { $0.xprotectRules(reply: $1) } completion: { data in
            completion(data.flatMap { try? JSONDecoder().decode(XProtectRuleStatus.self, from: $0) })
        }
    }
}
