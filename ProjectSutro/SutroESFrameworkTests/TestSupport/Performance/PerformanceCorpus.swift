//
//  PerformanceCorpus.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - A recording to measure
extension XCTestCase {
    /// The event types a recording is mostly made of, which the store, import, export and filter benchmarks use.
    static let recordingEventTypes: Set<String> = [
        "ES_EVENT_TYPE_NOTIFY_EXEC", "ES_EVENT_TYPE_NOTIFY_FORK", "ES_EVENT_TYPE_NOTIFY_EXIT",
        "ES_EVENT_TYPE_NOTIFY_OPEN", "ES_EVENT_TYPE_NOTIFY_CLOSE", "ES_EVENT_TYPE_NOTIFY_CREATE",
        "ES_EVENT_TYPE_NOTIFY_MMAP",
    ]

    /// A recording's worth of events: the synthetic corpus's full exec, fork, exit, open, close, create and mmap (every
    /// key filled), and the eslogger lineage fixture's ten real execs, forks and exits, in turn.
    ///
    /// Each event is moved in time and given one of 3,000 processes, about three events each, as the trace import
    /// tests do, so the store shares rows across batches as it does for a real recording.
    ///
    /// - Parameter count: How many events.
    /// - Returns: The events, in time order.
    /// - Throws: The error making up an event or reading the fixture.
    func recordingEvents(_ count: Int) throws -> [Message] {
        let synthetic = try SyntheticCorpus.records()
            .filter { $0.variant.name == "full" && Self.recordingEventTypes.contains($0.message.es_event_type) }
            .map(\.message)
        let kinds = synthetic + (try lineageTrace())
        return (0..<count).map { index in
            var message = kinds[index % kinds.count]
            message.mach_time = Int64(index)
            let pid = Int32(index / 3 % 3_000 + 100)
            message.process.pid = pid
            if var token = message.process.audit_token {
                (token.pid, token.pidversion) = (pid, pid)
                message.process.audit_token = token
                message.process.audit_token_string = token.toString()
            }
            return message
        }
    }

    /// ``recordingEvents(_:)`` as a JSONL trace, one exported record per line, as File > Open Trace... reads one.
    ///
    /// - Parameter count: How many events.
    /// - Returns: The trace's file, deleted when the test ends.
    /// - Throws: The error making the events or writing the file.
    func recordingTrace(_ count: Int) throws -> URL {
        let lines = try recordingEvents(count).map(exportText)
        return try temporaryFile(containing: lines.joined(separator: "\n"), named: "trace.jsonl")
    }
}
