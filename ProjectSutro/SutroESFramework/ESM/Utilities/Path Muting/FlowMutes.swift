//
//  FlowMutes.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
import EndpointSecurity


// MARK: - Mutes for network flows
/// The path mutes a capture session's network lane applies to flows, which Endpoint Security can't mute: its process
/// mutes (``MuteList``, `ES_MUTE_PATH_TYPE_LITERAL` and `ES_MUTE_PATH_TYPE_PREFIX`) whose scope is every event or
/// names the flow's event, matched against the path of the flow's process.
///
/// A target mute never applies, since a flow has no target path. A flow whose process path isn't known is never
/// muted. Paths compare byte for byte, as Endpoint Security compares them.
struct FlowMutes: Equatable {
    /// One event's muted paths.
    private struct Paths: Equatable {
        var literals = Set<String>()
        var prefixes: [String] = []
    }

    /// Each flow event's muted paths.
    private var paths: [MacMonitorEvent: Paths] = [:]

    /// No mutes.
    init() {}

    /// The process mutes of a list that cover each flow event.
    ///
    /// - Parameter list: The session's mutes, such as the saved mute set.
    init(_ list: MuteList) {
        for (key, scope) in list.scopes {
            let isLiteral = key.type == ES_MUTE_PATH_TYPE_LITERAL
            guard isLiteral || key.type == ES_MUTE_PATH_TYPE_PREFIX else { continue }
            for event in MacMonitorEvent.allCases {
                if case .events(let events) = scope, !events.contains(event.type) { continue }
                if isLiteral {
                    paths[event, default: Paths()].literals.insert(key.path)
                } else {
                    paths[event, default: Paths()].prefixes.append(key.path)
                }
            }
        }
    }

    /// Is a flow's process muted for its event?
    ///
    /// - Parameters:
    ///   - path: The path of the flow's process, or `nil` when it isn't known.
    ///   - event: The flow's event.
    /// - Returns: `true` when a literal mute is the path, or a prefix mute starts it.
    func mutes(_ path: String?, for event: MacMonitorEvent) -> Bool {
        guard let path, let muted = paths[event] else { return false }
        /// A set finds strings that are canonically equal. The bytes must be the same too.
        if let index = muted.literals.firstIndex(of: path), muted.literals[index].utf8.elementsEqual(path.utf8) {
            return true
        }
        return muted.prefixes.contains { path.utf8.starts(with: $0.utf8) }
    }
}
