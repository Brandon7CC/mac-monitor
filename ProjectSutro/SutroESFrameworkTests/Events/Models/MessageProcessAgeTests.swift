//
//  MessageProcessAgeTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Process ages
/// Pins ``Message/deriveProcessAges()``: every process gets its age at the event from its start time and the message's
/// time, at capture and for any message without one. Nothing here opens the event store.
final class MessageProcessAgeTests: XCTestCase {
    /// The raw fixture's message time is 1_791_072_114.394127173: this start is 14 s and 0.173 µs before it.
    private static let start = timeval(tv_sec: 1_791_072_100, tv_usec: 394_127)

    /// Every process of a message: the initiating one, then the event's.
    ///
    /// - Parameter message: The message.
    /// - Returns: The processes.
    private func processes(of message: Message) -> [SutroESFramework.Process] {
        var event = message.event, all = [message.process]
        event.forEachProcess { all.append($0) }
        return all
    }

    /// A full synthetic event with no ages, every process started at `start`, recorded at `time`.
    ///
    /// - Parameters:
    ///   - label: The synthetic record's label prefix, such as `signal `.
    ///   - start: Every process's start time.
    ///   - time: The message's time.
    /// - Returns: The event.
    /// - Throws: The error making the corpus, or an `XCTest` failure if it has no such record.
    private func synthetic(_ label: String, start: TimeVal, time: Date) throws -> Message {
        let record = try XCTUnwrap(try SyntheticCorpus.records().first { $0.label.hasPrefix(label) && $0.variant.full })
        var message = record.message
        message.message_darwin_time = time
        message.process.start_time = start
        message.process.process_age_ms = nil
        message.event.forEachProcess { $0.start_time = start; $0.process_age_ms = nil }
        return message
    }

    /// A time value without a random id worth keeping.
    ///
    /// - Parameters:
    ///   - seconds: `tv_sec`.
    ///   - microseconds: `tv_usec`.
    /// - Returns: The value.
    private func timeVal(_ seconds: Int, _ microseconds: Int = 0) -> TimeVal {
        TimeVal(from: timeval(tv_sec: seconds, tv_usec: Int32(microseconds)))
    }

    // MARK: Capture

    /// A captured event's initiating process is dated against the message: 14,000 ms old, rounded.
    func testCaptureDerivesTheInitiatingProcessAge() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXIT)
        fixture.message.pointee.process.pointee.start_time = Self.start
        XCTAssertEqual(Message(from: fixture.raw).process.process_age_ms, 14_000)
    }

    /// A process Endpoint Security gives no start time (all zeros) has no age.
    func testCaptureLeavesAnUnknownStartWithoutAge() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXIT)
        XCTAssertNil(Message(from: fixture.raw).process.process_age_ms)
    }

    /// A captured signal dates its instigator and its target too, each against its own start.
    func testCaptureDerivesTheEventsProcesses() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_SIGNAL)
        let target = fixture.process(path: "/usr/bin/yes"), instigator = fixture.process(path: "/bin/kill")
        target.pointee.start_time = timeval(tv_sec: 1_791_068_514, tv_usec: 394_127)
        instigator.pointee.start_time = Self.start
        fixture.message.pointee.event.signal.target = target
        fixture.message.pointee.event.signal.instigator = instigator
        fixture.message.pointee.event.signal.sig = SIGTERM
        guard case .signal(let signal) = Message(from: fixture.raw).event else { return XCTFail("Not a signal") }
        XCTAssertEqual(signal.target.process_age_ms, 3_600_000)
        XCTAssertEqual(signal.instigator?.process_age_ms, 14_000)
    }

    // MARK: Deriving

    /// Every process of every event type that carries one is dated: 2.5 s here.
    func testEveryProcessIsDerived() throws {
        let time = Date(timeIntervalSince1970: 1_791_072_102.5)
        for record in try SyntheticCorpus.records() where record.variant.full {
            var message = try synthetic(record.label, start: timeVal(1_791_072_100), time: time)
            message.deriveProcessAges()
            let ages = processes(of: message).map(\.process_age_ms)
            XCTAssertEqual(ages, Array(repeating: 2_500, count: ages.count), record.label)
        }
    }

    /// Microseconds count, and the result is rounded to the nearest millisecond.
    func testAgeIsRoundedToMilliseconds() throws {
        let time = Date(timeIntervalSince1970: 1_791_072_101)
        var message = try synthetic("exit ", start: timeVal(1_791_072_100, 999_400), time: time)
        message.deriveProcessAges()
        XCTAssertEqual(message.process.process_age_ms, 1)
        message.process.process_age_ms = nil
        message.process.start_time = timeVal(1_791_072_100, 998_400)
        message.deriveProcessAges()
        XCTAssertEqual(message.process.process_age_ms, 2)
    }

    /// A start after the message's time (the clock stepped back) is kept as a negative age.
    func testNegativeAgeIsKept() throws {
        let time = Date(timeIntervalSince1970: 1_791_072_100)
        var message = try synthetic("fork ", start: timeVal(1_791_072_103), time: time)
        message.deriveProcessAges()
        XCTAssertEqual(processes(of: message).map(\.process_age_ms), [-3_000, -3_000])
    }

    /// A start time of 0 or before is unknown: no age.
    func testUnknownStartGivesNoAge() throws {
        for seconds in [0, -1] {
            var message = try synthetic("exec ", start: timeVal(seconds, 5), time: Date())
            message.deriveProcessAges()
            XCTAssertEqual(processes(of: message).map(\.process_age_ms), [nil, nil], "tv_sec \(seconds)")
        }
    }

    /// An age a process already has, from the recording Mac, is never derived again.
    func testExistingAgeIsKept() throws {
        let time = Date(timeIntervalSince1970: 1_791_072_102.5)
        var message = try synthetic("signal ", start: timeVal(1_791_072_100), time: time)
        message.process.process_age_ms = 99
        message.event.forEachProcess { $0.process_age_ms = -7 }
        message.deriveProcessAges()
        XCTAssertEqual(processes(of: message).map(\.process_age_ms), [99, -7, -7])
    }

    /// The age changes nothing a process's row is shared by: two events of one process share one row key.
    func testAgeIsNotPartOfTheRowKey() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXIT)
        fixture.message.pointee.process.pointee.start_time = Self.start
        var older = Message(from: fixture.raw).process
        older.process_age_ms = 1
        var newer = older
        newer.process_age_ms = 2_000
        XCTAssertEqual(older.rowKey, newer.rowKey)
        XCTAssertNil(older.rowKey.process_age_ms)
    }

    // MARK: Wire

    /// A message from a 3.0.0 Security Extension has no ages: it decodes, and the app derives them.
    func testWireWithoutAgesDecodes() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXIT)
        fixture.message.pointee.process.pointee.start_time = Self.start
        var object = try jsonObject(try JSONEncoder().encode(Message(from: fixture.raw)))
        XCTAssertEqual(object[path: "process", "process_age_ms"] as? Int, 14_000)
        object[path: "process", "process_age_ms"] = nil
        var older = try JSONDecoder().decode(Message.self, from: try JSONSerialization.data(withJSONObject: object))
        XCTAssertNil(older.process.process_age_ms)
        older.deriveProcessAges()
        XCTAssertEqual(older.process.process_age_ms, 14_000)
    }
}
