//
//  IndicatorAlertPolicy.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Which matches notify
/// Which of an event's indicator hits a notification is for, if any.
///
/// A hit is eligible when its stamped severity's switch is on (Low never is), the Security Extension evaluated it as
/// it captured the event, this user hasn't silenced it, and it isn't known to be off: a batch stamped just before
/// someone turned an indicator off may still be on its way. An indicator this Mac Monitor doesn't know yet, such as one
/// `macmonitor` just added, isn't suppressed. An event gives at most one candidate, its strongest eligible hit, ties
/// going to the set's order. Its other hits, eligible or not, are only named.
public enum IndicatorAlertPolicy {
    /// The notification an event may give.
    ///
    /// - Parameters:
    ///   - message: The event, as it arrives from the Security Extension.
    ///   - settings: This user's notification settings.
    ///   - disabled: The indicators known to be off.
    ///   - appUser: This app's user.
    /// - Returns: The candidate, or `nil` when no hit is eligible or the event wasn't evaluated.
    public static func pick(_ message: Message, settings: IndicatorAlertSettings, disabled: Set<UUID>,
                            appUser: uid_t = getuid()) -> IndicatorAlertEvent? {
        guard let hits = message.indicators?.hits, !hits.isEmpty else { return nil }
        var top = -1
        for index in hits.indices where isEligible(hits[index], settings: settings, disabled: disabled) {
            if top < 0 || hits[index].severity > hits[top].severity { top = index }
        }
        guard top >= 0 else { return nil }
        return IndicatorAlertEvent(message, top: hits[top], others: named(hits, besides: top),
                                   moreOthers: max(0, hits.count - 3), appUser: appUser)
    }

    /// The names of the two of an event's other hits a notification names: the strongest first, in the set's order
    /// within a severity. One pass picks both, so nothing is sorted or gathered.
    ///
    /// - Parameters:
    ///   - hits: The event's hits.
    ///   - top: The notification's hit, by index.
    /// - Returns: Up to two names.
    private static func named(_ hits: [IndicatorHit], besides top: Int) -> [String] {
        guard hits.count > 1 else { return [] }
        var (first, second) = (-1, -1)
        for index in hits.indices where index != top {
            let severity = hits[index].severity
            if first < 0 || severity > hits[first].severity {
                (first, second) = (index, first)
            } else if second < 0 || severity > hits[second].severity {
                second = index
            }
        }
        return second < 0 ? [hits[first].name] : [hits[first].name, hits[second].name]
    }

    /// - Parameters:
    ///   - hit: One of an event's hits.
    ///   - settings: This user's notification settings.
    ///   - disabled: The indicators known to be off.
    /// - Returns: May it notify?
    static func isEligible(_ hit: IndicatorHit, settings: IndicatorAlertSettings, disabled: Set<UUID>) -> Bool {
        settings.notifies(for: hit.severity) && hit.evaluated_by == .securityExtension
            && (settings.silenced.isEmpty || !settings.silenced.contains(hit.id))
            && (disabled.isEmpty || !disabled.contains(hit.id))
    }

    /// How old an event is, by the wall clock, as a Clear compares times: under Rosetta this process's
    /// `mach_absolute_time()` and the Security Extension's differ.
    ///
    /// - Parameters:
    ///   - event: The event.
    ///   - now: The time now.
    /// - Returns: Its age in seconds, never negative.
    public static func age(of event: IndicatorAlertEvent, now: Date) -> TimeInterval {
        max(0, now.timeIntervalSince(event.time))
    }
}
