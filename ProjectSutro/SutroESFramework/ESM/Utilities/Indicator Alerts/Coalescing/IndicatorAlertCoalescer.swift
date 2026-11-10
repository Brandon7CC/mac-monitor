//
//  IndicatorAlertCoalescer.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Coalescing
/// Decides which notifications indicator matches post, and when, on an injected clock (uptime seconds), so a build
/// that matches Mach-O written a thousand times a minute posts a handful.
///
/// - A match on an idle indicator takes a token from its severity's bucket and posts its first notice at once, which
///   opens a window of the indicator's current length. Without a token, a Medium goes to the overflow summary, and a
///   High waits for the High bucket's next token: a High is never folded into the overflow.
/// - A match inside a window, or while a High waits, is gathered. When the window ends, a summary replaces the
///   indicator's notice (it needs a token, two for Medium so one is kept for first notices), and the next window
///   doubles, up to 15 minutes. A Medium summary the bucket refuses moves to the overflow. An indicator with no match
///   for 15 minutes starts over at one minute.
/// - A Medium event older than ``IndicatorAlertLimits/staleAfter``, such as a spooled backlog, goes only to the
///   overflow summary.
/// - The overflow summary gathers for 10 seconds, then posts at most once a minute, less often while it keeps
///   filling.
///
/// No match is lost: the counts of everything posted add up to the matches observed, once their windows end. State is
/// in memory only. It's a value type: use it on one queue, and call ``tick(now:)`` at ``nextDeadline``.
public struct IndicatorAlertCoalescer: Sendable {
    /// One indicator's state.
    struct Slot: Sendable {
        /// Its latest match's severity.
        var severity: IndicatorSeverity
        /// Its window's length, now.
        var length: TimeInterval
        /// When its window ends, or when a waiting High tries for a token again.
        var end = -TimeInterval.infinity
        /// Its latest match.
        var lastMatch = -TimeInterval.infinity
        /// When it was first tracked, to break ties between windows that end together.
        let order: Int
        /// A High's first notice, waiting for a token.
        var waiting: IndicatorAlertEvent?
        /// The matches gathered for its next summary.
        var folded: IndicatorAlertSummary?

        /// Is anything waiting to post?
        var isPending: Bool { waiting != nil || folded != nil }
    }

    /// The numbers it follows.
    public let limits: IndicatorAlertLimits
    /// Each indicator's state, by identity.
    private(set) var slots: [UUID: Slot] = [:]
    /// Tokens for Medium notices and summaries.
    private var medium: AlertTokenBucket
    /// Tokens for High notices and summaries.
    private var high: AlertTokenBucket
    /// The overflow summary's matches and timing.
    private(set) var overflow: OverflowState
    /// Slots tracked so far, for ``Slot/order``.
    private var tracked = 0
    /// Never later than the earliest end of a slot with something waiting, so ``tick(now:)`` looks at the slots only
    /// once one may be due: most matches fold into an open window.
    private var slotsDue = TimeInterval.infinity

    /// - Parameter limits: The numbers it follows.
    public init(limits: IndicatorAlertLimits = .standard) {
        self.limits = limits
        medium = AlertTokenBucket(capacity: limits.mediumBurst, every: limits.mediumRefill)
        high = AlertTokenBucket(capacity: limits.highBurst, every: limits.highRefill)
        overflow = OverflowState(interval: limits.overflowFirstInterval)
    }

    /// Take a match: an event's candidate (``IndicatorAlertPolicy``).
    ///
    /// - Parameters:
    ///   - event: The event.
    ///   - now: The clock now.
    ///   - age: How old the event is, by the wall clock (``IndicatorAlertPolicy/age(of:now:)``).
    /// - Returns: What to post now: what was due (``tick(now:)``), then the event's notice, if it gets one.
    public mutating func observe(_ event: IndicatorAlertEvent, now: TimeInterval,
                                 age: TimeInterval = 0) -> [IndicatorAlert] {
        var posts = tick(now: now)
        let id = event.indicator.id
        /// Taken out while it changes, so what it gathered isn't copied.
        var slot = slots.removeValue(forKey: id) ?? newSlot(event.indicator.severity)
        if now - slot.lastMatch >= limits.idleReset { slot.length = limits.firstWindow }
        slot.lastMatch = now
        slot.severity = event.indicator.severity
        defer {
            if slot.isPending { slotsDue = min(slotsDue, slot.end) }
            slots[id] = slot
            evictIfFull(now: now)
        }
        if slot.severity != .high && age > limits.staleAfter {
            overflow.add(event.indicator, count: 1, latest: event, now: now, limits: limits)
        } else if now < slot.end || slot.isPending {
            fold(event, into: &slot)
        } else if take(for: slot.severity, now: now) {
            posts.append(.first(event))
            slot.end = now + slot.length
        } else if slot.severity != .high {
            overflow.add(event.indicator, count: 1, latest: event, now: now, limits: limits)
        } else {
            slot.waiting = event
            slot.end = high.nextToken(now: now)
        }
        return posts
    }

    /// Post what's due: windows that ended with matches gathered, Highs whose token came back, and the overflow.
    ///
    /// - Parameter now: The clock now.
    /// - Returns: What to post, in order.
    public mutating func tick(now: TimeInterval) -> [IndicatorAlert] {
        var posts: [IndicatorAlert] = []
        if now >= slotsDue { posts = tickSlots(now: now) }
        if let summary = overflow.take(now: now, limits: limits) { posts.append(.overflow(summary)) }
        return posts
    }

    /// Post the slots that are due, and find when the next one is.
    ///
    /// - Parameter now: The clock now.
    /// - Returns: What to post, in order.
    private mutating func tickSlots(now: TimeInterval) -> [IndicatorAlert] {
        var posts: [IndicatorAlert] = []
        var due: [(end: TimeInterval, order: Int, id: UUID)] = []
        for (id, slot) in slots where slot.isPending && now >= slot.end { due.append((slot.end, slot.order, id)) }
        due.sort { ($0.end, $0.order) < ($1.end, $1.order) }
        for (_, _, id) in due {
            guard var slot = slots.removeValue(forKey: id) else { continue }
            if let waiting = slot.waiting {
                if high.take(now: now) {
                    posts.append(.first(waiting))
                    (slot.waiting, slot.end) = (nil, now + slot.length)
                } else {
                    slot.end = high.nextToken(now: now)
                }
            } else if let folded = slot.folded {
                if take(for: slot.severity, now: now, summary: true) {
                    posts.append(.summary(folded))
                } else if slot.severity != .high {
                    overflow.add(folded.latest.indicator, count: folded.count, latest: folded.latest, now: now,
                                 limits: limits)
                } else {
                    slot.end = high.nextToken(now: now)
                    slots[id] = slot
                    continue
                }
                slot.folded = nil
                slot.length = min(slot.length * 2, limits.maxWindow)
                slot.end = now + slot.length
            }
            slots[id] = slot
        }
        slotsDue = slots.values.lazy.filter(\.isPending).map(\.end).min() ?? .infinity
        return posts
    }

    /// When ``tick(now:)`` next has something to post, or `nil` when nothing waits: then no timer is needed.
    public var nextDeadline: TimeInterval? {
        let ends = slots.values.lazy.filter(\.isPending).map(\.end)
        return (Array(ends) + (overflow.isEmpty ? [] : [overflow.due])).min()
    }

    /// Forget the matches of indicators that may no longer notify, such as a severity switched off or an indicator
    /// silenced, so nothing gathered for them posts later.
    ///
    /// - Parameter shouldDrop: Given an indicator's identity and severity, should it be forgotten?
    public mutating func drop(where shouldDrop: (UUID, IndicatorSeverity) -> Bool) {
        slots = slots.filter { !shouldDrop($0.key, $0.value.severity) }
        overflow.drop { shouldDrop($0.id, $0.severity) }
    }

    // MARK: Helpers

    /// - Parameter severity: Its first match's severity.
    /// - Returns: A new indicator's state.
    private mutating func newSlot(_ severity: IndicatorSeverity) -> Slot {
        tracked += 1
        return Slot(severity: severity, length: limits.firstWindow, order: tracked)
    }

    /// Gather a match into an indicator's next summary.
    ///
    /// - Parameters:
    ///   - event: The match.
    ///   - slot: The indicator's state.
    private func fold(_ event: IndicatorAlertEvent, into slot: inout Slot) {
        guard slot.folded != nil else { return slot.folded = IndicatorAlertSummary(event) }
        slot.folded?.add(event, limit: limits.distinctProcesses)
    }

    /// Take a token for a severity's notification.
    ///
    /// - Parameters:
    ///   - severity: The notification's severity.
    ///   - now: The clock now.
    ///   - summary: Is it a summary? A Medium one needs more tokens than it takes.
    /// - Returns: Was one taken?
    private mutating func take(for severity: IndicatorSeverity, now: TimeInterval, summary: Bool = false) -> Bool {
        guard severity != .high else { return high.take(now: now) }
        return medium.take(now: now, need: summary ? limits.mediumSummaryNeeds : 1)
    }

    /// Past ``IndicatorAlertLimits/trackedIndicators``, forget the indicator matched least recently. One that has
    /// matches waiting moves them to the overflow, so none is lost.
    ///
    /// - Parameter now: The clock now.
    private mutating func evictIfFull(now: TimeInterval) {
        guard slots.count > limits.trackedIndicators,
              let (id, oldest) = slots.min(by: { $0.value.lastMatch < $1.value.lastMatch }) else { return }
        slots[id] = nil
        for summary in [oldest.waiting.map(IndicatorAlertSummary.init), oldest.folded].compactMap({ $0 }) {
            overflow.add(summary.latest.indicator, count: summary.count, latest: summary.latest, now: now,
                         limits: limits)
        }
    }
}
