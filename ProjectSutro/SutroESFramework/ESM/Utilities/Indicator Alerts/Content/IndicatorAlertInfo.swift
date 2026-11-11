//
//  IndicatorAlertInfo.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - What a click acts on
/// What a notification carries for a click: its kind, the event to open, and the indicators to search for. It's all a
/// notification's `userInfo` holds, as UUID strings, since macOS keeps it with the notification: no event facts.
public struct IndicatorAlertInfo: Equatable, Sendable {
    /// What kind of notification it is.
    public enum Kind: String, Sendable {
        /// An indicator's first notice.
        case first
        /// A summary of its later matches.
        case summary
        /// The overflow summary.
        case overflow
    }

    /// The Show All Matches action's identifier.
    public static let showAllAction = "indicator.show-all"
    /// The Don't Notify for This Indicator action's identifier.
    public static let dontNotifyAction = "indicator.dont-notify"

    /// What kind of notification it is.
    public let kind: Kind
    /// The event a click opens: the notice's, a summary's latest, or the overflow's first listed indicator's latest.
    public let eventID: UUID
    /// The indicator it's for: for the overflow, the first it lists.
    public let indicatorID: UUID
    /// For the overflow, every indicator it holds. Empty otherwise.
    public let indicators: [UUID]

    /// - Parameters:
    ///   - kind: What kind of notification it is.
    ///   - eventID: The event a click opens.
    ///   - indicatorID: The indicator it's for.
    ///   - indicators: For the overflow, every indicator it holds.
    public init(kind: Kind, eventID: UUID, indicatorID: UUID, indicators: [UUID]) {
        (self.kind, self.eventID, self.indicatorID, self.indicators) = (kind, eventID, indicatorID, indicators)
    }

    /// - Parameter overflow: The overflow summary, which holds at least one indicator.
    init(_ overflow: IndicatorAlertOverflow) {
        let first = overflow.entries.first
        self.init(kind: .overflow, eventID: first?.latest.eventID ?? UUID(), indicatorID: first?.indicator.id ?? UUID(),
                  indicators: overflow.entries.map(\.indicator.id))
    }

    /// Read back from a notification's `userInfo`.
    ///
    /// - Parameter userInfo: The notification's `userInfo`.
    /// - Returns: `nil` when it isn't one of these, such as a notification from another build.
    public init?(userInfo: [AnyHashable: Any]) {
        guard let kind = (userInfo["kind"] as? String).flatMap(Kind.init(rawValue:)),
              let event = (userInfo["event"] as? String).flatMap(UUID.init(uuidString:)),
              let indicator = (userInfo["indicator"] as? String).flatMap(UUID.init(uuidString:)) else { return nil }
        let listed = (userInfo["indicators"] as? [String] ?? []).compactMap(UUID.init(uuidString:))
        self.init(kind: kind, eventID: event, indicatorID: indicator, indicators: listed)
    }

    /// The notification's `userInfo`: `event`, `indicator` and `kind`, and `indicators` for the overflow.
    public var userInfo: [String: Any] {
        var info: [String: Any] = ["event": eventID.uuidString, "indicator": indicatorID.uuidString,
                                   "kind": kind.rawValue]
        if kind == .overflow { info["indicators"] = indicators.map(\.uuidString) }
        return info
    }

    /// The search that shows its matches in the main window: `ANY indicators.id == "<uuid>"` for an indicator's,
    /// and for the overflow, `ANY indicators.id IN {...}` of every indicator it holds.
    public var search: String {
        guard kind == .overflow else { return #"ANY indicators.id == "\#(indicatorID.uuidString)""# }
        return StreamFilter.Predicate.listing(indicators, for: .search)?.source ?? ""
    }
}
