//
//  SequenceGapCounterTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Sequence gaps
/// Pins how drops are counted from Endpoint Security's sequence numbers, as `ESMessage.h` describes them.
final class SequenceGapCounterTests: XCTestCase {
    /// A fresh counter fed a stream of numbers.
    ///
    /// - Parameter sequence: The numbers, in order.
    /// - Returns: The counter.
    private func counted(_ sequence: [UInt64]) -> SequenceGapCounter {
        var counter = SequenceGapCounter()
        sequence.forEach { counter.observe($0) }
        return counter
    }
    
    /// A contiguous stream has no drops, whatever it starts at.
    func testContiguousNumbersHaveNoDrops() {
        let counter = counted(Array(1_000...1_999))
        XCTAssertEqual(counter.dropped, 0)
        XCTAssertEqual(counter.gaps, 0)
        XCTAssertEqual(counter.regressions, 0)
        XCTAssertEqual(counter.last, 1_999)
    }
    
    /// Missing numbers are drops, and each run of them is one gap.
    func testMissingNumbersAreDrops() {
        let counter = counted([0, 1, 2, 5, 6, 10, 11])
        XCTAssertEqual(counter.dropped, 2 + 3)
        XCTAssertEqual(counter.gaps, 2)
    }
    
    /// A repeat or a step back is a regression, not a drop, and counting carries on from it.
    func testRepeatsAndStepsBackAreRegressions() {
        let counter = counted([5, 6, 6, 3, 4, 5])
        XCTAssertEqual(counter.regressions, 2)
        XCTAssertEqual(counter.dropped, 0)
        XCTAssertEqual(counter.last, 5)
    }
    
    /// Interleaved types with contiguous numbers have no drops. A drop shows in the global stream and in its type's.
    func testDropsAreNamedByType() {
        let exec = Int(ES_EVENT_TYPE_NOTIFY_EXEC.rawValue), open = Int(ES_EVENT_TYPE_NOTIFY_OPEN.rawValue)
        var tracker = ClientSequenceTracker()
        /// (type, `seq_num`, `global_seq_num`): global 2, an open with `seq_num` 1, is dropped.
        for (type, sequence, global) in [(exec, 0, 0), (open, 0, 1), (exec, 1, 3), (open, 2, 4), (exec, 2, 5)] {
            tracker.observe(eventType: type, sequence: UInt64(sequence), globalSequence: UInt64(global))
        }
        XCTAssertEqual(tracker.global.dropped, 1)
        XCTAssertEqual(tracker.droppedByType(), [open: 1])
        XCTAssertEqual(tracker.droppedByType().byEventTypeName(), ["ES_EVENT_TYPE_NOTIFY_OPEN": 1])
    }
    
    /// A drop of a type that never comes again only shows in the global stream.
    func testTrailingDropOnlyShowsGlobally() {
        let exec = Int(ES_EVENT_TYPE_NOTIFY_EXEC.rawValue), close = Int(ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue)
        var tracker = ClientSequenceTracker()
        for (type, sequence, global) in [(close, 0, 0), (exec, 0, 2), (exec, 1, 3)] {
            tracker.observe(eventType: type, sequence: UInt64(sequence), globalSequence: UInt64(global))
        }
        XCTAssertEqual(tracker.global.dropped, 1)
        XCTAssertTrue(tracker.droppedByType().isEmpty)
    }
    
    /// An event type past the tracker's initial room grows it.
    func testNewerEventTypesGrowTheTracker() {
        var tracker = ClientSequenceTracker(eventTypeCount: 4)
        tracker.observe(eventType: 300, sequence: 0, globalSequence: 0)
        tracker.observe(eventType: 300, sequence: 2, globalSequence: 1)
        XCTAssertEqual(tracker.droppedByType(), [300: 1])
    }
    
    /// A message's numbers are only read from the versions that have them: `seq_num` from 2, `global_seq_num` from 4.
    func testMessageVersionsGateTheNumbers() {
        let exit = Int(ES_EVENT_TYPE_NOTIFY_EXIT.rawValue)
        var tracker = ClientSequenceTracker()
        tracker.observe(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, seq: 0, global: 1, version: 1).raw)
        tracker.observe(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, seq: 2, global: 2, version: 3).raw)
        tracker.observe(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, seq: 5, global: 9, version: 4).raw)
        XCTAssertEqual(tracker.global.dropped, 0)
        XCTAssertEqual(tracker.droppedByType(), [exit: 2])
    }
    
    /// A file client's tracker where two closes a field filter left out make gaps, and one open was really dropped.
    ///
    /// - Returns: The tracker: `global_seq_num` lost 3 and 4 (closes 2 and 3), `seq_num` lost close 2 and 3 and
    ///   open 2.
    private func trackerWithLeftOutCloses() -> ClientSequenceTracker {
        let open = Int(ES_EVENT_TYPE_NOTIFY_OPEN.rawValue), close = Int(ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue)
        var tracker = ClientSequenceTracker()
        for (type, sequence, global) in [(open, 1, 1), (close, 1, 2), (close, 4, 5), (open, 3, 6)] {
            tracker.observe(eventType: type, sequence: UInt64(sequence), globalSequence: UInt64(global))
        }
        return tracker
    }
    
    /// Drops counted without some types are the other types' `seq_num` gaps alone.
    func testDropsCanLeaveTypesUncounted() {
        let open = Int(ES_EVENT_TYPE_NOTIFY_OPEN.rawValue), close = Int(ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue)
        let tracker = trackerWithLeftOutCloses()
        XCTAssertEqual(tracker.global.dropped, 2)
        XCTAssertEqual(tracker.dropped(uncounting: [close]), 1)
        XCTAssertEqual(tracker.dropped(uncounting: []), 3)
        XCTAssertEqual(tracker.dropped(uncounting: [close, open]), 0)
    }
    
    /// A report that leaves a type uncounted holds only the other types' drops. One that leaves none uncounted is the
    /// report it always was.
    func testReportsCanLeaveTypesUncounted() {
        let close = Int(ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue)
        let tracker = trackerWithLeftOutCloses()
        var uncounting = DropReportMark()
        XCTAssertEqual(uncounting.takeReport(of: .file, from: tracker, uncounting: [close]), CaptureDropReport(
            eventClass: .file, dropped: 1, droppedByType: ["ES_EVENT_TYPE_NOTIFY_OPEN": 1]))
        XCTAssertNil(uncounting.takeReport(of: .file, from: tracker, uncounting: [close]))
        var counting = DropReportMark()
        XCTAssertEqual(counting.takeReport(of: .file, from: tracker), CaptureDropReport(
            eventClass: .file, dropped: 2,
            droppedByType: ["ES_EVENT_TYPE_NOTIFY_OPEN": 1, "ES_EVENT_TYPE_NOTIFY_CLOSE": 2]))
        XCTAssertNil(counting.takeReport(of: .file, from: tracker, uncounting: []))
    }
    
    /// Changing what's counted between reports never traps, and never makes an empty report, even when the new count
    /// is below the last. Counting a type again reports its drops as new.
    func testChangingWhatsCountedNeverTraps() {
        let close = Int(ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue)
        let tracker = trackerWithLeftOutCloses()
        var mark = DropReportMark()
        XCTAssertNotNil(mark.takeReport(of: .file, from: tracker))
        XCTAssertNil(mark.takeReport(of: .file, from: tracker, uncounting: [close]), "1 is below the 2 reported")
        XCTAssertEqual(mark.takeReport(of: .file, from: tracker), CaptureDropReport(
            eventClass: .file, dropped: 1, droppedByType: ["ES_EVENT_TYPE_NOTIFY_CLOSE": 2]))
    }
}
