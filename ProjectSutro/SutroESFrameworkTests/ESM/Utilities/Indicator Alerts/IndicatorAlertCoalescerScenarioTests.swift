//
//  IndicatorAlertCoalescerScenarioTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The simulation's scenarios
/// Pins the coalescer to the simulation its numbers were picked with (`indicator-alert-scenarios.json`): every
/// scenario's posts, at the same times, with the same counts, and every match covered by a post. Each scenario's
/// matches are made as the simulation makes them, in the same order, so equal times sort the same way.
final class IndicatorAlertCoalescerScenarioTests: XCTestCase {
    /// Fourteen Mediums, each once a second for an hour.
    private static let flood = (0..<14).flatMap { key in
        (0..<3600).map { ScenarioMatch(time: Double($0) + Double(key) * 0.01, key: key, severity: .medium) }
    }

    /// Each scenario's matches, by its number in the simulation.
    private static let scenarios: [String: [ScenarioMatch]] = [
        "1": stride(from: 0.0, to: 600, by: 0.005).map { ScenarioMatch(time: $0, key: 1, severity: .medium) },
        "2": stride(from: 0.0, to: 10800, by: 2).map { ScenarioMatch(time: $0, key: 2, severity: .medium) },
        "3": (0..<5).flatMap { minute in
            (0..<10).map { ScenarioMatch(time: Double(minute * 60) + Double($0) * 0.01, key: 100 + $0,
                                         severity: .medium) }
        },
        "4": stride(from: 0.0, to: 120, by: 0.01).map { ScenarioMatch(time: $0, key: 1, severity: .medium) }
            + (0..<5).map { ScenarioMatch(time: 30, key: 200 + $0, severity: .medium) }
            + [ScenarioMatch(time: 30.5, key: 9, severity: .high)],
        "5": (0..<500).map { ScenarioMatch(time: 5 + Double($0) * 0.001, key: 3, severity: .medium, age: 600) },
        "6": [ScenarioMatch(time: 0, key: 4, severity: .medium), ScenarioMatch(time: 1200, key: 4, severity: .medium)],
        "7": (0..<36000).map { ScenarioMatch(time: Double($0) / 10, key: 1, severity: .medium) },
        "8": (0..<500).map { ScenarioMatch(time: Double($0) * 0.06, key: 2, severity: .medium) }
            + (0..<40).map { ScenarioMatch(time: Double($0) * 0.75, key: 3, severity: .medium) },
        "9": flood,
        "10": flood + (0..<12).map { ScenarioMatch(time: Double($0) * 300 + 0.5, key: 100, severity: .high) },
        "12": (0..<9).map { ScenarioMatch(time: Double($0) * 1200, key: $0 % 3, severity: .medium) },
        "13": (0..<6).flatMap { build in
            stride(from: 0.0, to: 120, by: 0.02).map {
                ScenarioMatch(time: Double(build) * 600 + $0, key: 1, severity: .medium)
            }
        },
        "14": flood + [ScenarioMatch(time: 1800, key: 500, severity: .medium)],
    ]

    /// Run a scenario's matches.
    ///
    /// - Parameter matches: The matches.
    /// - Returns: The run.
    /// - Throws: The error making a candidate.
    private func run(_ matches: [ScenarioMatch]) throws -> ScenarioRun {
        var events: [Int: IndicatorAlertEvent] = [:]
        var keys: [UUID: Int] = [:]
        for match in matches where events[match.key] == nil {
            events[match.key] = try alertEvent(scenarioID(match.key), match.severity, name: "Indicator \(match.key)")
            keys[scenarioID(match.key)] = match.key
        }
        return ScenarioRun(matches, keys: keys, events: events)
    }

    /// Every scenario posts what the simulation posted, when it did, and covers every match.
    func testScenariosMatchTheSimulation() throws {
        let object = try fixtureObject("indicator-alert-scenarios.json")
        let expected = try XCTUnwrap(object["scenarios"] as? [String: [String]])
        XCTAssertEqual(Set(expected.keys), Set(Self.scenarios.keys))
        for (name, matches) in Self.scenarios.sorted(by: { Int($0.key)! < Int($1.key)! }) {
            let run = try run(matches)
            XCTAssertEqual(run.posts, expected[name], "Scenario \(name)")
            XCTAssertEqual(run.covered, matches.count, "Scenario \(name) lost matches")
        }
    }

    /// A Medium never seen before posts its own notice at once during a fourteen-indicator flood (scenario 14):
    /// the token a summary leaves.
    func testANewMediumPostsAtOnceDuringAFlood() throws {
        let run = try run(Self.scenarios["14"]!)
        let notice = run.alerts.first {
            if case .first(let event) = $0.alert { return event.indicator.id == scenarioID(500) }
            return false
        }
        XCTAssertEqual(notice?.time, 1800)
    }

    /// Highs never wait behind a Medium storm (scenario 10): each posts when it matches.
    func testHighsPostAtOnceDuringAFlood() throws {
        let run = try run(Self.scenarios["10"]!)
        let highs = run.alerts.filter {
            if case .first(let event) = $0.alert { return event.indicator.severity == .high }
            return false
        }
        XCTAssertEqual(highs.map(\.time), (0..<12).map { Double($0) * 300 + 0.5 })
    }

    /// Six Highs at once: five post, the sixth posts as a notice of its own at the next High token, 30 seconds on,
    /// and their repeats are summarized, none in the overflow and none lost.
    func testHighsBeyondTheirTokensWaitForTheNext() throws {
        let matches = (0..<6).map { ScenarioMatch(time: 0, key: 300 + $0, severity: .high) }
            + (0..<6).map { ScenarioMatch(time: 10, key: 300 + $0, severity: .high) }
        let run = try run(matches)
        XCTAssertEqual(run.covered, 12)
        let firsts = run.alerts.filter { if case .first = $0.alert { return true } else { return false } }
        XCTAssertEqual(firsts.map(\.time), [0, 0, 0, 0, 0, 30])
        XCTAssertFalse(run.alerts.contains { if case .overflow = $0.alert { return true } else { return false } })
    }
}
