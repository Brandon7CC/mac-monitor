//
//  EventTypeProcessesTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Every process a payload carries
/// Pins ``EventType/forEachProcess(_:)`` against reflection: every `Process` anywhere in a payload is visited, so an
/// event type that gains a process, or a new one that carries one, fails here until the walker visits it.
final class EventTypeProcessesTests: XCTestCase {
    /// The event types whose full synthetic variant carries a process, beside the initiating one.
    private static let typesWithProcesses: Set<String> = [
        "exec", "fork", "signal", "proc_suspend_resume", "proc_check", "remote_thread_create", "trace", "get_task",
        "btm_launch_item_add", "btm_launch_item_remove", "profile_add", "authorization_petition",
        "authorization_judgement", "od_create_user", "od_modify_password", "od_group_add", "od_group_remove",
        "od_create_group", "od_attribute_value_add", "tcc_modify",
    ]

    /// Every `Process` in a value, found by reflection, however deep, in declaration order.
    ///
    /// - Parameter value: The value: a payload, an optional, an array, or anything else.
    /// - Returns: The processes. A process's own children aren't searched: a process holds none.
    private func reflectedProcesses(in value: Any) -> [SutroESFramework.Process] {
        if let process = value as? SutroESFramework.Process { return [process] }
        return Mirror(reflecting: value).children.flatMap { reflectedProcesses(in: $0.value) }
    }

    /// The processes the walker visits.
    ///
    /// - Parameter event: The payload.
    /// - Returns: The processes, in the order they're visited.
    private func visitedProcesses(in event: EventType) -> [SutroESFramework.Process] {
        var event = event, visited: [SutroESFramework.Process] = []
        event.forEachProcess { visited.append($0) }
        return visited
    }

    /// For every synthetic event, full and empty, the walker visits exactly the processes reflection finds.
    func testEveryProcessIsVisited() throws {
        for record in try SyntheticCorpus.records() {
            let reflected = reflectedProcesses(in: record.message.event)
            let visited = visitedProcesses(in: record.message.event)
            XCTAssertEqual(visited.map(\.id), reflected.map(\.id), record.label)
        }
    }

    /// The event types that carry a process are the ones expected, so the corpus does exercise every arm.
    func testEventTypesWithProcesses() throws {
        let full = try SyntheticCorpus.records().filter { $0.variant.full }
        let carrying = Set(full.filter { !visitedProcesses(in: $0.message.event).isEmpty }
            .map { String($0.label.prefix { $0 != " " }) })
        XCTAssertEqual(carrying, Self.typesWithProcesses)
        let signal = try XCTUnwrap(full.first { $0.label.hasPrefix("signal ") })
        XCTAssertEqual(visitedProcesses(in: signal.message.event).count, 2, "A signal's instigator and target")
    }

    /// A change the walker's body makes is kept in the payload, for every process.
    func testChangesAreKept() throws {
        for record in try SyntheticCorpus.records() where record.variant.full {
            var event = record.message.event
            event.forEachProcess { $0.process_age_ms = -42 }
            let ages = reflectedProcesses(in: event).map(\.process_age_ms)
            XCTAssertEqual(ages, Array(repeating: -42, count: ages.count), record.label)
        }
    }

    /// A process Endpoint Security left out isn't visited.
    func testMissingProcessesAreSkipped() throws {
        let empty = try SyntheticCorpus.records().filter { !$0.variant.full }
        let signal = try XCTUnwrap(empty.first { $0.label.hasPrefix("signal ") })
        XCTAssertEqual(visitedProcesses(in: signal.message.event).count, 1, "Only the target")
        let tcc = try XCTUnwrap(empty.first { $0.label.hasPrefix("tcc_modify ") })
        XCTAssertEqual(visitedProcesses(in: tcc.message.event).count, 0)
    }
}
