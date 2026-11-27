//
//  NetworkStatisticsClient+Loss.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Losses
extension NetworkStatisticsClient {
    /// What the loss checks keep from one tick to the next.
    struct LossState {
        /// When the last check of the open flows started, the flows it has yet to query, and when it may query more.
        var checkStarted = -TimeInterval.infinity
        var checking: [UInt64] = []
        var nextBatch = -TimeInterval.infinity
        /// The kernel's add failures and the client's lost sources at the last look, and when that was.
        var failures: UInt32?
        var lost = 0
        var looked = -TimeInterval.infinity
        /// Other clients' failures since the window began, and when one was last seen.
        var others = 0
        var window = -TimeInterval.infinity
        var lastOther = -TimeInterval.infinity
        /// When the socket was last reopened, how fast other clients' failures came before it, a second, and how
        /// long until the next reopen may come.
        var reopened = -TimeInterval.infinity
        var rateBeforeReopen: Double?
        var reopenWait = NetworkStatisticsClient.reopenInterval
        /// When the flows not seen again since the reopen are given up.
        var giveUpInherited: TimeInterval?
    }

    /// How often open flows are checked at most, how many are queried a tick, how far apart the ticks are, and
    /// how few bytes must be waiting for a tick to query or poll.
    static let checkInterval: TimeInterval = 10, checkBatch = 200, checkSpacing: TimeInterval = 0.1,
               checkBelow = 1 << 20
    /// How often the kernel's add failures are looked at, and the shortest and longest wait between reopens.
    static let failureInterval: TimeInterval = 5, reopenInterval: TimeInterval = 60,
               longestReopenWait: TimeInterval = 1_800
    /// The most datagrams a reopen reads from the old socket before closing it.
    static let reopenReadLimit = 16 * readLimit

    /// After a sign that the kernel dropped a message, query the open flows to find the ones whose removal was lost.
    /// One the kernel no longer has (`ENOENT`) closes without its counts.
    ///
    /// - Parameter now: The time, in seconds of uptime.
    /// - Returns: When it's next due, or `nil` when it isn't.
    func checkLosses(_ now: TimeInterval) -> TimeInterval? {
        guard let table, let socket else { return nil }
        if loss.checking.isEmpty, table.lossSignalled, now - loss.checkStarted >= Self.checkInterval {
            (table.lossSignalled, loss.checkStarted, loss.checking) = (false, now, table.openFlows())
        }
        if !loss.checking.isEmpty, now >= loss.nextBatch, socket.pending() < Self.checkBelow {
            for reference in loss.checking.suffix(Self.checkBatch) where table.sources[reference] != nil {
                _ = send(.check(reference))
            }
            loss.checking.removeLast(min(Self.checkBatch, loss.checking.count))
            loss.nextBatch = now + Self.checkSpacing
        }
        if !loss.checking.isEmpty { return max(loss.nextBatch, now + Self.checkSpacing) }
        return table.lossSignalled ? loss.checkStarted + Self.checkInterval : nil
    }

    /// On macOS 13 and 14 the kernel offers each new socket to its clients newest first, and stops at the first that
    /// can't queue it. Every older client misses it, with no gap in its source references. So every 5 s the
    /// kernel's count of adds it couldn't queue for any client is compared with the client's own lost sources. Any
    /// more are another client's. They're counted, and answered by reopening (``answerOtherClients(at:)``). A
    /// minute with none sets the wait between reopens back to a minute.
    ///
    /// - Parameter now: The time, in seconds of uptime.
    /// - Returns: When it's next due, or `nil` on a macOS that doesn't need it.
    func checkAddFailures(_ now: TimeInterval) -> TimeInterval? {
        guard darwin == 22 || darwin == 23, let table else { return nil }
        if let due = loss.giveUpInherited, now >= due {
            table.dropInherited()
            loss.giveUpInherited = nil
        }
        guard now - loss.looked >= Self.failureInterval else { return loss.looked + Self.failureInterval }
        let failures = addFailures(), lost = table.counts.lostSources
        if let failures, let before = loss.failures {
            let others = Int(failures &- before) - (lost - loss.lost)
            if others > 0 {
                table.counts.otherClientFailures += others
                (loss.others, loss.lastOther) = (loss.others + others, now)
            } else if now - loss.lastOther >= Self.reopenInterval {
                (loss.others, loss.window, loss.rateBeforeReopen) = (0, now, nil)
                loss.reopenWait = Self.reopenInterval
            }
            if loss.others > 0, now - loss.reopened >= loss.reopenWait { answerOtherClients(at: now) }
        } else {
            loss.window = now
        }
        (loss.failures, loss.lost, loss.looked) = (failures, lost, now)
        return now + Self.failureInterval
    }

    /// Reopen for other clients' failures, unless they came at least as fast since the last reopen as before it.
    /// Those are an older client's, which a reopen doesn't help, so the next reopen waits twice as long instead,
    /// up to 30 minutes.
    ///
    /// - Parameter now: The time, in seconds of uptime.
    private func answerOtherClients(at now: TimeInterval) {
        let rate = Double(loss.others) / max(now - loss.window, Self.failureInterval)
        if let before = loss.rateBeforeReopen, rate >= before {
            loss.reopenWait = min(2 * loss.reopenWait, Self.longestReopenWait)
        } else {
            reopen(at: now)
            loss.rateBeforeReopen = rate
        }
        (loss.others, loss.window) = (0, now)
    }

    /// Move to the head of the kernel's list of clients. Read what the old socket holds, then ask a new one for
    /// every source and close the old one. Nothing is read from the old one once the new one is asked, or a source
    /// both see then would be recorded twice. The new table carries on the old one's flows, matched when their
    /// sources are seen again (``FlowSourceTable/inherited``). The ones not seen within 5 s closed in between.
    ///
    /// - Parameter now: The time, in seconds of uptime.
    func reopen(at now: TimeInterval) {
        guard let old = socket, let previous = table, let made = try? makeSocket() else { return }
        readDatagrams(limit: Self.reopenReadLimit)
        let clock = clock(), refused = subscribe(made)
        old.close()
        let replacement = makeTable(clock: clock, replacing: previous)
        replacement.counts.reopens += 1
        replacement.providersOff = refused
        start(made, table: replacement)
        current.receiveBuffer = made.receiveBuffer
        // A check of the old socket's flows would query the new one's sources by the old one's references.
        (loss.checking, loss.nextBatch) = ([], -.infinity)
        (loss.reopened, loss.giveUpInherited) = (now, now + Self.failureInterval)
    }
}
