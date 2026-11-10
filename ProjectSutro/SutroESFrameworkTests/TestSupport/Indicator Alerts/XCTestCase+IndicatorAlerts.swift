//
//  XCTestCase+IndicatorAlerts.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Events for notification tests
extension XCTestCase {
    /// An indicator's hit, as the Security Extension stamps it.
    ///
    /// - Parameters:
    ///   - name: The indicator's name.
    ///   - severity: Its severity.
    ///   - id: Its identity.
    ///   - evaluatedBy: Who matched it.
    /// - Returns: The hit, tactic Persistence and technique T1543.001.
    func alertHit(_ name: String, _ severity: IndicatorSeverity = .medium, id: UUID = UUID(),
                  evaluatedBy: IndicatorEvaluator = .securityExtension) -> IndicatorHit {
        var indicator = ownIndicator(name, Self.execCheck, severity: severity)
        indicator.id = id
        indicator.tactic = .persistence
        indicator.technique = "T1543.001"
        return IndicatorHit(indicator, isDefault: false, evaluatedBy: evaluatedBy)
    }

    /// The synthetic corpus's first exec, as it arrives with verdicts.
    ///
    /// - Parameters:
    ///   - hits: Its verdicts' hits, or `nil` for an event nothing evaluated.
    ///   - time: When it happened.
    ///   - change: Changes it further.
    /// - Returns: The event, with an identity of its own.
    /// - Throws: The error making the corpus.
    func alertMessage(_ hits: [IndicatorHit]?, time: Date = Date(),
                      _ change: (inout Message) -> Void = { _ in }) throws -> Message {
        var message = try corpusExec()
        message.id = UUID()
        message.message_darwin_time = time
        message.indicators = hits.map(IndicatorVerdicts.init)
        change(&message)
        return message
    }

    /// A candidate for an indicator: what the coalescer takes.
    ///
    /// - Parameters:
    ///   - id: The indicator's identity.
    ///   - severity: Its severity.
    ///   - name: Its name.
    ///   - time: When the event happened.
    ///   - path: The process's executable.
    /// - Returns: The candidate.
    /// - Throws: The error making the event.
    func alertEvent(_ id: UUID, _ severity: IndicatorSeverity = .medium, name: String = "Mach-O written",
                    time: Date = Date(), path: String = "/usr/bin/tool") throws -> IndicatorAlertEvent {
        let hit = alertHit(name, severity, id: id)
        let message = try alertMessage([hit], time: time) { $0.process.executable?.path = path }
        return IndicatorAlertEvent(message, top: hit, others: [])
    }

    /// The identity a simulation scenario gives an indicator key: `00000000-0000-0000-0000-0000000000<key>`.
    ///
    /// - Parameter key: The key.
    /// - Returns: The identity.
    func scenarioID(_ key: Int) -> UUID {
        UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", key))!
    }
}


// MARK: - Simulation scenarios
/// One match in a scenario: when, which indicator, its severity, and how old its event is.
struct ScenarioMatch {
    let time: TimeInterval
    let key: Int
    let severity: IndicatorSeverity
    var age: TimeInterval = 0
}

/// Runs a coalescer through matches as the scheduler's one-shot timer would: at each next match or deadline,
/// whichever comes first.
struct ScenarioRun {
    /// Each post, as the simulation prints it: `60.00s:1:11999`, its time, `s` for a summary or `o` for the
    /// overflow, its indicator key (-1 for the overflow) and its count.
    private(set) var posts: [String] = []
    /// Every match a post stands for.
    private(set) var covered = 0
    /// The posts, by kind and time, for checks of their own.
    private(set) var alerts: [(time: TimeInterval, alert: IndicatorAlert)] = []

    /// - Parameters:
    ///   - matches: The matches, in any order.
    ///   - keys: Each indicator identity's key.
    ///   - events: Each key's candidate, reused for every match.
    ///   - limits: The numbers the coalescer follows.
    init(_ matches: [ScenarioMatch], keys: [UUID: Int], events: [Int: IndicatorAlertEvent],
         limits: IndicatorAlertLimits = .standard) {
        var coalescer = IndicatorAlertCoalescer(limits: limits)
        let sorted = matches.sorted { $0.time < $1.time }
        var next = 0
        while true {
            let match = next < sorted.count ? sorted[next].time : .infinity
            let deadline = coalescer.nextDeadline ?? .infinity
            if match == .infinity && deadline == .infinity { break }
            if deadline < match {
                record(coalescer.tick(now: deadline), at: deadline, keys: keys)
            } else {
                let found = sorted[next]
                record(coalescer.observe(events[found.key]!, now: found.time, age: found.age), at: found.time,
                       keys: keys)
                next += 1
            }
        }
    }

    /// - Parameters:
    ///   - posted: What the coalescer posted.
    ///   - time: When.
    ///   - keys: Each indicator identity's key.
    private mutating func record(_ posted: [IndicatorAlert], at time: TimeInterval, keys: [UUID: Int]) {
        for alert in posted {
            let (tag, key): (String, Int) = switch alert {
            case .first(let event): ("", keys[event.indicator.id]!)
            case .summary(let summary): ("s", keys[summary.latest.indicator.id]!)
            case .overflow: ("o", -1)
            }
            posts.append(String(format: "%.2f%@:%d:%d", time, tag, key, alert.count))
            covered += alert.count
            alerts.append((time, alert))
        }
    }
}
