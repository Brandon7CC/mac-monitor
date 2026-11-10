//
//  IndicatorAlertEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - An event to notify for
/// What a notification may say of an event that matched an indicator: copied out of the event once, as it arrives, so
/// nothing else of it is held. It never holds the event's `context`, which for an exec is its command line, nor an
/// exec's arguments, environment or script, its working directory, a file's content, a cdhash or an audit token:
/// notification text is kept by macOS and can show on a locked screen.
public struct IndicatorAlertEvent: Hashable, Sendable {
    /// The indicator a notification is for, as the Security Extension stamped it on the event.
    public struct Match: Hashable, Sendable {
        /// Its identity.
        public let id: UUID
        /// Its name.
        public let name: String
        /// Its severity, as stamped: not what Settings says now.
        public let severity: IndicatorSeverity
        /// Its ATT&CK tactic's name, or `nil`.
        public let tactic: String?
        /// Its ATT&CK technique, or `nil`.
        public let technique: String?

        /// - Parameter hit: The indicator's hit on the event.
        public init(_ hit: IndicatorHit) {
            (id, name, severity, tactic, technique) = (hit.id, hit.name, hit.severity, hit.tactic, hit.technique)
        }
    }

    /// The event's identity, which Event Facts opens.
    public let eventID: UUID
    /// When it happened, by the wall clock.
    public let time: Date
    /// The indicator the notification is for: the event's strongest eligible hit.
    public let indicator: Match
    /// Up to two of the event's other hits' names, the strongest first.
    public let others: [String]
    /// How many more other hits it has.
    public let moreOthers: Int
    /// The process's executable, or `nil` when Endpoint Security gave none.
    public let executablePath: String?
    /// Its process identifier.
    public let pid: Int32
    /// The process's user when it isn't this app's, such as `root`, or `nil`.
    public let user: String?
    /// The process's signing identifier, or `nil`.
    public let signingID: String?
    /// Is the process ad hoc signed?
    public let isAdHoc: Bool
    /// Is the process unsigned?
    public let isUnsigned: Bool
    /// The event's `ES_EVENT_TYPE_*` name. A notification shows its short name (``eventName``).
    public let eventType: String
    /// The path the event acted on, or `nil`.
    public let targetPath: String?

    /// - Parameters:
    ///   - message: The event.
    ///   - top: The hit the notification is for.
    ///   - others: The event's other hits, the strongest first. Two are named.
    ///   - otherCount: How many other hits the event has, when `others` holds only some: at least their count.
    ///   - appUser: This app's user, whose processes aren't named by user.
    public init(_ message: Message, top: IndicatorHit, others: [IndicatorHit], otherCount: Int? = nil,
                appUser: uid_t = getuid()) {
        let named = others.prefix(2).map(\.name)
        self.init(message, top: top, others: named, moreOthers: max(0, (otherCount ?? others.count) - named.count),
                  appUser: appUser)
    }

    /// - Parameters:
    ///   - message: The event.
    ///   - top: The hit the notification is for.
    ///   - others: Up to two of the event's other hits' names, the strongest first.
    ///   - moreOthers: How many more other hits it has.
    ///   - appUser: This app's user, whose processes aren't named by user.
    init(_ message: Message, top: IndicatorHit, others: [String], moreOthers: Int, appUser: uid_t) {
        eventID = message.id
        time = message.message_darwin_time
        indicator = Match(top)
        (self.others, self.moreOthers) = (others, moreOthers)
        executablePath = message.process.executable?.path
        pid = message.process.pid
        if let euid = message.process.euid, euid != Int(appUser) {
            user = message.process.euid_human ?? "uid \(euid)"
        } else {
            user = nil
        }
        isAdHoc = message.process.is_adhoc_signed || message.process.codesigning_type == .adhoc
        isUnsigned = message.process.signing_id == nil || message.process.codesigning_type == .unsigned
        signingID = isUnsigned ? nil : message.process.signing_id
        eventType = message.es_event_type
        targetPath = message.target_path
    }

    /// The event's short name, such as `create`: worked out only when a notification is written.
    public var eventName: String { CommandLineEvents.shortName(eventType) }

    /// The process, as a summary counts distinct ones: its executable, or its pid without one.
    var processKey: String { executablePath ?? "pid \(pid)" }
}
