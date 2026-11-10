//
//  IndicatorAlertScheduler.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Scheduling notifications
/// Runs an ``IndicatorAlertCoalescer`` on a serial queue of its own, with one one-shot timer armed for its next
/// deadline: nothing repeats and nothing polls, and while nothing waits no timer is armed. Each batch of candidates,
/// and each deadline, hands what's due to `post`.
///
/// **Threading:** thread-safe. `post` is called on its queue.
public final class IndicatorAlertScheduler: @unchecked Sendable {
    /// Posts notifications, on the scheduler's queue.
    public typealias Post = @Sendable ([IndicatorAlert]) -> Void

    private let queue: DispatchQueue
    private let post: Post
    /// Uptime in seconds, the coalescer's clock.
    private let clock: @Sendable () -> TimeInterval
    /// The wall clock, for an event's age.
    private let wallClock: @Sendable () -> Date
    /// How late the timer may fire, so the system can group wake-ups.
    private let leeway: DispatchTimeInterval
    /// Only used on ``queue``.
    private var coalescer: IndicatorAlertCoalescer
    /// The deadline the timer is armed for, or `nil` when it isn't. Only used on ``queue``.
    private var armed: TimeInterval?
    private let timer: DispatchSourceTimer

    /// - Parameters:
    ///   - limits: The numbers the coalescer follows.
    ///   - label: Its queue's label.
    ///   - leeway: How late the timer may fire.
    ///   - clock: Uptime in seconds: the same clock as `DispatchTime`'s.
    ///   - wallClock: The wall clock.
    ///   - post: Posts what's due, on its queue.
    public init(limits: IndicatorAlertLimits = .standard, label: String = "com.swiftlydetecting.agent.indicator-alerts",
                leeway: DispatchTimeInterval = .seconds(1),
                clock: @escaping @Sendable () -> TimeInterval = { Double(DispatchTime.now().uptimeNanoseconds) / 1e9 },
                wallClock: @escaping @Sendable () -> Date = { Date() }, post: @escaping Post) {
        queue = DispatchQueue(label: label)
        coalescer = IndicatorAlertCoalescer(limits: limits)
        (self.post, self.clock, self.wallClock, self.leeway) = (post, clock, wallClock, leeway)
        timer = DispatchSource.makeTimerSource(queue: queue)
        timer.setEventHandler { [weak self] in self?.fire() }
        timer.schedule(deadline: .distantFuture)
        timer.resume()
    }

    deinit {
        timer.cancel()
    }

    /// Take a batch of candidates whose events were inserted.
    ///
    /// - Parameter events: The candidates, oldest first.
    public func receive(_ events: [IndicatorAlertEvent]) {
        queue.async { [self] in
            let (now, wall) = (clock(), wallClock())
            let posts = events.flatMap {
                coalescer.observe($0, now: now, age: IndicatorAlertPolicy.age(of: $0, now: wall))
            }
            settle(posts)
        }
    }

    /// Forget the matches of indicators that may no longer notify (``IndicatorAlertCoalescer/drop(where:)``).
    ///
    /// - Parameter shouldDrop: Given an indicator's identity and severity, should it be forgotten?
    public func drop(where shouldDrop: @escaping @Sendable (UUID, IndicatorSeverity) -> Bool) {
        queue.async { [self] in
            coalescer.drop(where: shouldDrop)
            settle([])
        }
    }

    /// Wait until what was handed over before is done: for tests.
    func sync() {
        queue.sync {}
    }

    /// A deadline came: post what's due. The timer fired, so the clock is taken to be at least its deadline.
    private func fire() {
        let now = max(clock(), armed ?? -.infinity)
        armed = nil
        settle(coalescer.tick(now: now))
    }

    /// Post what's due, and arm the timer for the next deadline, or disarm it.
    ///
    /// - Parameter posts: What's due.
    private func settle(_ posts: [IndicatorAlert]) {
        if !posts.isEmpty { post(posts) }
        let deadline = coalescer.nextDeadline
        guard deadline != armed else { return }
        armed = deadline
        guard let deadline else { return timer.schedule(deadline: .distantFuture) }
        let delay = max(0, deadline - clock())
        timer.schedule(deadline: .now() + delay, repeating: .never, leeway: leeway)
    }
}
