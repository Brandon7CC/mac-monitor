//
//  TraceImporterProcessAgeTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Process ages of opened traces
/// Pins how ``TraceImporter/message(from:)`` gives processes their ages: a record without one (eslogger's, or an
/// export from 3.0.0) gets it derived from its own `start_time` and `time`, unless that time is 2.1.0's local time,
/// and a record's own is kept.
final class TraceImporterProcessAgeTests: XCTestCase {
    /// The eslogger exit fixture's process started at 2026-10-04T00:00:01.000001Z and exited at
    /// 2026-10-04T00:01:55.281215406Z: 114.281214406 s.
    private static let exitAge = 114_281

    /// eslogger writes no age: the exiting process's lifetime is derived.
    func testEsloggerAgeIsDerived() throws {
        let message = try TraceImporter.message(from: try fixture("eslogger-exit.jsonl"))
        XCTAssertEqual(message.process.process_age_ms, Self.exitAge)
    }

    /// A record's own age, from the Mac that recorded it, is kept, even one that's negative.
    func testRecordedAgeIsKept() throws {
        for recorded in [5, -250] {
            var record = try fixtureObject("eslogger-exit.jsonl")
            record[path: "process", "process_age_ms"] = recorded
            XCTAssertEqual(try importRecord(record).process.process_age_ms, recorded)
        }
    }

    /// A `null` age, as an export writes an unknown one, is derived again from the record's own fields.
    func testNullAgeIsDerived() throws {
        var record = try fixtureObject("eslogger-exit.jsonl")
        record[path: "process", "process_age_ms"] = NSNull()
        XCTAssertEqual(try importRecord(record).process.process_age_ms, Self.exitAge)
    }

    /// A start time of 0, or none at all, gives no age.
    func testUnknownStartGivesNoAge() throws {
        var zero = try fixtureObject("eslogger-exit.jsonl")
        zero[path: "process", "start_time"] = "1970-01-01T00:00:00.000000Z"
        XCTAssertNil(try importRecord(zero).process.process_age_ms)
        var missing = try fixtureObject("eslogger-exit.jsonl")
        missing[path: "process", "start_time"] = nil
        XCTAssertNil(try importRecord(missing).process.process_age_ms)
    }

    /// A 2.1.0 export's `time` is the recording Mac's local time, read in this Mac's time zone, while its start times
    /// are UTC: no age is derived from it, since it would be off by the zones' difference. The same record with its
    /// exact `message_darwin_time` is dated.
    func testLocalTimeGivesNoAge() throws {
        let legacy = "macmonitor-2.1-exit.jsonl"
        XCTAssertNil(try TraceImporter.message(from: try fixture(legacy)).process.process_age_ms)
        var exact = try fixtureObject(legacy)
        let time = try XCTUnwrap(ESLogger.date(fromTime: "2026-10-03T23:01:57.289Z", legacy: false))
        exact["message_darwin_time"] = time.timeIntervalSinceReferenceDate
        /// Started at 2026-10-03T23:00:01.000001Z: 116.288999 s.
        XCTAssertEqual(try importRecord(exact).process.process_age_ms, 116_289)
    }

    /// An exec's target and a fork's child are dated too, each from its own start time.
    func testEventProcessesAreDerived() throws {
        var target = try shell()
        target["start_time"] = "2026-10-04T00:01:54.281215Z"
        guard case .exec(let exec) = try execMessage(by: try shell(), of: target).event else {
            return XCTFail("Not an exec")
        }
        XCTAssertEqual(exec.target.process_age_ms, 1_000)
        var child = try shell()
        child["process_age_ms"] = 3
        let fork = try forkMessage(by: try shell(), of: child)
        XCTAssertEqual(fork.process.process_age_ms, Self.exitAge)
        XCTAssertEqual(fork.event.fork?.child.process_age_ms, 3)
    }
}
