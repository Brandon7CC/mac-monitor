//
//  MessageYaraScanTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/26/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Asking for an event's scan
/// Pins what asking for an event's scan costs (``Message/requestYaraScan(of:from:volumes:)``). Every event of every
/// lane asks, so an event that isn't scanned, or one on a lane that doesn't scan, allocates nothing.
final class MessageYaraScanTests: XCTestCase {
    /// An open, closes and an exec on a lane without the scanner, and an open, an unmodified close and an exec that
    /// runs no script on one with it, allocate nothing and get no ticket, once each has been asked about before.
    func testAnEventThatIsntScannedAllocatesNothing() throws {
        try XCTSkipUnless(AllocationCounter.isAvailable, "malloc_logger isn't there to count with.")
        let scanner = try makeScanner()
        scanner.acquire()
        defer { scanner.release() }
        let volumes = LocalVolumes()
        let open = sequencedMessage(ES_EVENT_TYPE_NOTIFY_OPEN, global: 1)
        open.message.pointee.event.open.file = open.file("/tmp/f")
        let unmodified = closeMessage(modified: false, global: 2)
        let modified = closeMessage(modified: true, global: 3)
        let exec = try importRecord(try esloggerExec(parent: (1, 1)))
        let cases: [(String, Message, RawMessageFixture, FileScanner?)] = [
            ("open", Message(from: open.raw), open, nil),
            ("unmodified close", Message(from: unmodified.raw), unmodified, nil),
            ("modified close", Message(from: modified.raw), modified, nil),
            ("exec", exec, open, nil),
            ("open, scanning", Message(from: open.raw), open, scanner),
            ("unmodified close, scanning", Message(from: unmodified.raw), unmodified, scanner),
            ("exec, scanning", exec, open, scanner),
        ]
        for (name, event, fixture, scanner) in cases {
            var warm = event
            _ = warm.requestYaraScan(of: fixture.raw, from: scanner, volumes: volumes)
            var message = event
            var ticket: FileScanTicket?
            let allocations = AllocationCounter.counting {
                ticket = message.requestYaraScan(of: fixture.raw, from: scanner, volumes: volumes)
            }
            XCTAssertNil(ticket, name)
            XCTAssertEqual(allocations, 0, name)
        }
    }
}
