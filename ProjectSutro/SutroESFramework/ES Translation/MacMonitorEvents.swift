//
//  MacMonitorEvents.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
import EndpointSecurity


// MARK: - Mac Monitor's own events
/// Mac Monitor's own events, which no Endpoint Security message makes: the network flows the Security Extension reads
/// from the kernel's network statistics socket.
///
/// Their numbers are far past `ES_EVENT_TYPE_LAST` (172 in the macOS 27.2 SDK), so no Endpoint Security type takes
/// them. A flow's `Message` carries the number as its `event_type` and the name as its `es_event_type`, between the
/// Security Extension and its clients. The record has neither: those keys mean Endpoint Security.
public enum MacMonitorEvent: UInt32, CaseIterable, Sendable {
    case new_flow = 1001
    case flow_closed = 1002

    /// One past the highest number: what a table by event type is sized to.
    public static let typeLimit = 1_003

    /// The event's type, as a table by type keys it.
    public var type: es_event_type_t { es_event_type_t(rawValue: rawValue) }

    /// Its name: its full name, its short name and its payload's key alike, as in `new_flow`. Spelled out, since
    /// `"\(self)"` reflects on the case and allocates on every call.
    public var name: String {
        switch self {
        case .new_flow: "new_flow"
        case .flow_closed: "flow_closed"
        }
    }

    /// - Parameter type: An event type.
    public init?(_ type: es_event_type_t) {
        self.init(rawValue: type.rawValue)
    }

    /// - Parameter name: A name, as in `new_flow`, matched exactly.
    public init?(name: String) {
        guard let event = Self.byName[name] else { return nil }
        self = event
    }

    /// Each event by its name.
    private static let byName = Dictionary(uniqueKeysWithValues: allCases.map { ($0.name, $0) })
}


// MARK: - Names
/// The names of every event Mac Monitor knows, Endpoint Security's and its own.
///
/// An Endpoint Security event's full name is its `ESTypes.h` name, and its short name that without the NOTIFY prefix,
/// in lowercase, as eslogger names events. Mac Monitor's own events have one name for both.
public enum EventNames {
    /// The prefix every NOTIFY event's full name has.
    public static let notifyPrefix = "ES_EVENT_TYPE_NOTIFY_"
    /// What the app's labels put before a network event's name, so it sorts beside the NOTIFY events.
    static let networkLabelPrefix = "NETWORK_"

    /// An event's short name.
    ///
    /// - Parameter fullName: A full name.
    /// - Returns: `exec` for `ES_EVENT_TYPE_NOTIFY_EXEC`, and `new_flow` for `new_flow`. A name without the NOTIFY
    ///   prefix comes back lowercased.
    public static func shortName(_ fullName: String) -> String {
        fullName.droppingPrefix(notifyPrefix).lowercased()
    }

    /// An event's full name.
    ///
    /// - Parameter name: A short name in any case, or a full name.
    /// - Returns: `ES_EVENT_TYPE_NOTIFY_EXEC` for `exec`, and `new_flow` for `NEW_FLOW`.
    public static func fullName(_ name: String) -> String {
        if name.hasPrefix(notifyPrefix) { return name }
        let lowercased = name.lowercased()
        return MacMonitorEvent(name: lowercased) != nil ? lowercased : notifyPrefix + name.uppercased()
    }

    /// The app's label for an event: the full name, or `NETWORK_NEW_FLOW` for a network event.
    ///
    /// - Parameter fullName: A full name.
    /// - Returns: The label.
    public static func label(_ fullName: String) -> String {
        MacMonitorEvent(name: fullName) != nil ? networkLabelPrefix + fullName.uppercased() : fullName
    }

    /// An event's short label, as the chart's bars and short lists name it.
    ///
    /// - Parameter fullName: A full name.
    /// - Returns: `EXEC` for `ES_EVENT_TYPE_NOTIFY_EXEC`, and `NEW_FLOW` for `new_flow`.
    public static func chartLabel(_ fullName: String) -> String {
        shortName(fullName).uppercased()
    }
}
