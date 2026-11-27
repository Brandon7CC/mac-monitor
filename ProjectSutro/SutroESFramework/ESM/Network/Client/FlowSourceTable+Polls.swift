//
//  FlowSourceTable+Polls.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Querying sources again
extension FlowSourceTable {
    /// When a pending source is queried again, after its first query or poll, and how many times at most.
    static let firstPoll: TimeInterval = 0.1, laterPolls: TimeInterval = 2, pollLimit = 5
    /// The most polls one pass sends. The rest are sent at the next pass, 0.1 s later.
    static let pollBatch = 200

    /// Polls in the order they're due. Each delay has a queue of its own, and the clock doesn't go back, so a poll
    /// added later is never due sooner. A pass reads only the polls that are due.
    struct PollQueue {
        private var entries: [(reference: UInt64, due: TimeInterval)] = []
        private var head = 0

        /// When the first poll is due, or `nil` when there's none.
        var next: TimeInterval? {
            head < entries.count ? entries[head].due : nil
        }

        /// Add a poll.
        ///
        /// - Parameters:
        ///   - reference: The source reference.
        ///   - due: When it's due, in seconds of uptime.
        mutating func append(_ reference: UInt64, due: TimeInterval) {
            entries.append((reference, due))
        }

        /// Take the first poll, if it's due.
        ///
        /// - Parameter now: The time, in seconds of uptime.
        /// - Returns: The poll, or `nil` when the first isn't due.
        mutating func take(dueBy now: TimeInterval) -> (reference: UInt64, due: TimeInterval)? {
            guard let next, next <= now else { return nil }
            let entry = entries[head]
            head += 1
            if head == entries.count {
                (entries, head) = ([], 0)
            } else if head >= 1_024, head * 2 >= entries.count {
                entries.removeFirst(head)
                head = 0
            }
            return entry
        }
    }

    /// A source's query wasn't answered, since the kernel couldn't queue the reply. Query it again soon while it's
    /// pending.
    ///
    /// - Parameter reference: Its source reference.
    func queryFailed(_ reference: UInt64) {
        guard var source = sources[reference] else { return }
        schedulePoll(&source, reference)
        sources[reference] = source
    }

    /// Query a pending source again, 0.1 s from now, then every 2 s, 5 times in all. A kernel TCP source that isn't
    /// connected at its first update is polled this way, so it opens at the poll after it connects. Darwin 22 has no
    /// event for that, and the one Darwin 23 and later have didn't come on macOS 27.2. So a source that connects after
    /// its last poll opens at its close.
    ///
    /// - Parameters:
    ///   - source: The source.
    ///   - reference: Its source reference.
    func schedulePoll(_ source: inout FlowSource, _ reference: UInt64) {
        guard source.polls < Self.pollLimit else { return }
        let soon = source.polls == 0
        source.nextPoll = clock.seconds + (soon ? Self.firstPoll : Self.laterPolls)
        if soon {
            pollsDue.soon.append(reference, due: source.nextPoll)
        } else {
            pollsDue.later.append(reference, due: source.nextPoll)
        }
    }

    /// Send the polls that are due, at most ``pollBatch``. A poll of a source that's gone, no longer pending, a
    /// listener, or rescheduled is passed over.
    ///
    /// - Parameter sending: May polls be sent? The client holds them back while its socket has many bytes waiting.
    /// - Returns: When the next poll is due, in seconds of uptime, or `nil` when none is. Polls still due are tried
    ///   again 0.1 s later.
    func poll(sending: Bool = true) -> TimeInterval? {
        let now = clock.seconds
        var sent = 0
        while sending, sent < Self.pollBatch,
              let (reference, due) = pollsDue.soon.take(dueBy: now) ?? pollsDue.later.take(dueBy: now) {
            guard var source = sources[reference], source.stage == .pending, !source.isListener,
                  source.nextPoll == due else { continue }
            source.polls += 1
            sent += 1
            _ = query(.query(reference))
            schedulePoll(&source, reference)
            sources[reference] = source
        }
        return pollsDue.soon.next.earlier(pollsDue.later.next).map { $0 > now ? $0 : now + Self.firstPoll }
    }

    /// The source references of the open and adopted flows, for a check that finds the ones whose removal was lost.
    ///
    /// - Returns: The references.
    func openFlows() -> [UInt64] {
        sources.compactMap { $0.value.stage == .open || $0.value.stage == .adopted ? $0.key : nil }
    }

    /// Stop waiting for the flows of the socket this one replaced. The ones not seen again closed in between, and
    /// their closes are lost.
    func dropInherited() {
        counts.closedDuringReopen += inherited.values.filter { $0.stage == .open || $0.stage == .adopted }.count
        inherited = [:]
    }
}


extension Optional where Wrapped == TimeInterval {
    /// The earlier of two times, for what's due next.
    ///
    /// - Parameter other: Another time, or `nil` for none.
    /// - Returns: The earlier, or the one that's there, or `nil` when neither is.
    func earlier(_ other: TimeInterval?) -> TimeInterval? {
        switch (self, other) {
        case let (this?, that?): Swift.min(this, that)
        case (nil, _): other
        case (_, nil): self
        }
    }
}
