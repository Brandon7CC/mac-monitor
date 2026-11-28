//
//  StreamCommand+Flows.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Network flows
/// What `macmonitor stream` says about the network flows a stream asked for. Flows have no sequence numbers, so no
/// gap shows what the stream lost of them: the Security Extension counts it.
extension StreamCommand {
    /// The warning for a stream that asked for flows and can't have them.
    ///
    /// - Parameters:
    ///   - stream: The stream that started.
    ///   - leftOut: Were the flows left out for an older Security Extension
    ///     (``withoutFlows(_:refusedBy:toolVersion:)``)?
    /// - Returns: Such as "macmonitor: network flows can't be streamed: Operation not permitted (errno 1)", or `nil`.
    static func flowWarning(_ stream: StreamStarted?, leftOut: Bool = false) -> String? {
        let reason = leftOut ? "this Security Extension doesn't know them"
            : stream?.networkProblem.map(TerminalSafeText.text)
        return reason.map { "macmonitor: network flows can't be streamed: \($0)" }
    }

    /// The same stream without the network flows, for a Security Extension of another version that refused it. One
    /// older than 3.3.0 doesn't know the flow events, and refuses a stream that names one.
    ///
    /// - Parameters:
    ///   - options: The stream asked for.
    ///   - reply: The Security Extension's answer.
    ///   - toolVersion: `macmonitor`'s own version.
    /// - Returns: The stream's other events, or `nil` when the Security Extension is this version or didn't refuse
    ///   the stream, or the stream names no flows or nothing else. No events would stream the defaults.
    static func withoutFlows(_ options: StreamOptions, refusedBy reply: StreamReply,
                             toolVersion: String) -> StreamOptions? {
        guard reply.status == .invalid, reply.sensorVersion != toolVersion else { return nil }
        var others = options
        others.events.removeAll { MacMonitorEvent(name: $0) != nil }
        return others.events.isEmpty || others.events.count == options.events.count ? nil : others
    }

    /// What the closing line adds for the flows that have no records.
    ///
    /// - Parameter summary: The Security Extension's summary.
    /// - Returns: Such as ", 3 sockets the kernel couldn't report, 120 flows over the rate limit", or "" for none.
    static func flowLosses(_ summary: StreamSummary) -> String {
        [(summary.networkSocketsLost, "socket", " the kernel couldn't report"),
         (summary.networkFlowsOverBudget, "flow", " over the rate limit")].compactMap { count, noun, phrase in
            count.flatMap { $0 > 0 ? ", \(String.counted($0, noun))\(phrase)" : nil }
        }.joined()
    }
}
