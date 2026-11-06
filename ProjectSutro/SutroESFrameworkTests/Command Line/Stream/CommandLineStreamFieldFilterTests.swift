//
//  CommandLineStreamFieldFilterTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - macmonitor stream and field filters
/// Runs `macmonitor stream` end to end, as ``CommandLineStreamTests`` does, over closes: by default only modified ones
/// are written, the gaps the rest leave are never reported as lost, and `--every close` writes them all.
final class CommandLineStreamFieldFilterTests: XCTestCase {
    private var savedMutes = SavedMuteSet(testing: MuteStore(directory: URL(fileURLWithPath: "/nonexistent")))
    private let utc = TextEventFormatter(timeZone: TimeZone(identifier: "UTC")!)
    /// A scope that suppresses nothing these events hold.
    private let nobody = PipelineScope(ancestry: [PipelineAncestor(pid: .max, groupID: 0, path: "/x/macmonitor")],
                                       includeSelf: false)
    /// Each close's `modified`, numbered from 1: three are left out, leaving gaps after closes 1 and 4.
    private let modified = [true, false, false, true, false, true]

    /// A saved set in a fresh directory.
    ///
    /// - Throws: If the directory can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        savedMutes = SavedMuteSet(testing: try makeMuteStore())
    }

    /// Stream the default events, or with `--every close`, hand the file client ``modified``'s closes, and stop.
    ///
    /// - Parameter every: Is `--every close` given?
    /// - Returns: The stream, stopped.
    /// - Throws: An `XCTest` failure if the stream never started or never stopped.
    private func streamCloses(every: Bool) throws -> StreamCommandRun {
        let harness = StreamHarness(savedMutes: savedMutes, serializer: MessageSerializer())
        let run = StreamCommandRun(harness: harness, formatter: .text(utc), scope: nobody)
        var invocation = StreamInvocation()
        if every { try CommandLineParser.every("close", in: &invocation) }
        run.start(invocation)
        XCTAssertTrue(waitUntil { !run.diagnostics.all.isEmpty }, "The stream never started.")
        let client = try XCTUnwrap(harness.factories.last).client(.file)
        for (offset, modified) in modified.enumerated() {
            let number = UInt64(offset + 1)
            client.deliver(closeMessage(modified: modified, seq: number, global: number))
        }
        let written = every ? modified.count : modified.filter { $0 }.count
        XCTAssertTrue(waitUntil { run.output.lines.count == written }, "\(run.output.lines)")
        run.command.stop()
        XCTAssertTrue(waitUntil { !run.reported.isEmpty })
        return run
    }

    /// By default only modified closes are written. The banner says so and how to see every close, nothing is lost,
    /// and the closing line says how many were left out.
    func testOnlyModifiedClosesByDefault() throws {
        let run = try streamCloses(every: false)
        XCTAssertEqual(run.output.lines.count, 3)
        XCTAssertEqual(run.diagnostics.all.count, 2, "\(run.diagnostics.all)")
        XCTAssertEqual(run.diagnostics.all.first?.hasSuffix("""
            (--no-mutes shows everything), only modified closes (--every close shows every close). Press Ctrl-C to \
            stop.
            """), true, "\(run.diagnostics.all)")
        XCTAssertEqual(run.diagnostics.all.last, """
            macmonitor: wrote 3 events, left out 3 unmodified closes, lost 0 (0 by Endpoint Security, 0 while \
            macmonitor was behind).
            """)
    }

    /// `--every close` writes every close, and the banner and closing line say nothing about filters.
    func testEveryCloseWritesThemAll() throws {
        let run = try streamCloses(every: true)
        XCTAssertEqual(run.output.lines.count, 6)
        XCTAssertEqual(run.diagnostics.all.first?.hasSuffix("(--no-mutes shows everything). Press Ctrl-C to stop."),
                       true, "\(run.diagnostics.all)")
        XCTAssertEqual(run.diagnostics.all.last, """
            macmonitor: wrote 6 events, lost 0 (0 by Endpoint Security, 0 while macmonitor was behind).
            """)
    }

    /// A Security Extension older than 3.0.1 echoes no filters: macmonitor warns, terminal or not, for each filter
    /// asked for on an event it streams, and counts every gap again.
    func testAnOlderSecurityExtensionIsWarnedAbout() {
        let (close, exec) = ("ES_EVENT_TYPE_NOTIFY_CLOSE", "ES_EVENT_TYPE_NOTIFY_EXEC")
        XCTAssertEqual(StreamCommand.unappliedFieldFilters(asked: [.modifiedCloses], events: [close]), [
            "macmonitor: this Security Extension streams every close. Open Mac Monitor to finish updating."
        ])
        XCTAssertEqual(StreamCommand.unappliedFieldFilters(asked: [.modifiedCloses], events: [exec]), [])
        XCTAssertEqual(StreamCommand.unappliedFieldFilters(asked: [], events: [close]), [])
        XCTAssertEqual(StreamCommand.fieldFilteredTypes(echoed: nil), [])
        XCTAssertEqual(StreamCommand.fieldFilteredTypes(echoed: [FieldFilter.modifiedCloses.rawValue, "later.x"]),
                       [Int(ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue)])
    }

    /// Against a Security Extension older than 3.0.1, which ignores the filter and echoes none, a stream that isn't on
    /// a terminal still says it gets every close, and reports a gap between closes as lost again.
    func testAnOlderSecurityExtensionCountsCloseGapsAsLost() throws {
        let harness = StreamHarness(savedMutes: savedMutes, serializer: MessageSerializer())
        let legacy = LegacyStreamHarness(relayingTo: harness)
        let run = StreamCommandRun(harness: harness, endpoint: legacy.endpoint, formatter: .text(utc), scope: nobody,
                                   isChatty: false)
        var invocation = StreamInvocation()
        invocation.events = [ES_EVENT_TYPE_NOTIFY_CLOSE]
        run.start(invocation)
        let warning = "macmonitor: this Security Extension streams every close. Open Mac Monitor to finish updating."
        XCTAssertTrue(waitUntil { run.diagnostics.all == [warning] }, "\(run.diagnostics.all)")
        let client = try XCTUnwrap(harness.factories.last).client(.file)
        client.deliver(closeMessage(modified: false, seq: 1, global: 1))
        client.deliver(closeMessage(modified: false, seq: 3, global: 3))
        XCTAssertTrue(waitUntil { run.output.lines.count == 2 }, "\(run.output.lines)")
        XCTAssertTrue(waitUntil { run.diagnostics.all.contains("macmonitor: lost 1 event (close 1)") },
                      "\(run.diagnostics.all)")
        run.command.stop()
        XCTAssertTrue(waitUntil { !run.reported.isEmpty })
        withExtendedLifetime(legacy) {}
    }

    /// The banner names only the filters applied, and the closing line only counts above zero. A count for an event
    /// this build has no filter for still reads.
    func testTheBannerAndClosingLineWords() {
        XCTAssertEqual(StreamCommand.keeping(echoed: nil), "")
        XCTAssertEqual(StreamCommand.keeping(echoed: []), "")
        XCTAssertEqual(StreamCommand.keeping(echoed: [FieldFilter.modifiedCloses.rawValue]),
                       ", only modified closes (--every close shows every close)")
        XCTAssertEqual(StreamCommand.leftOut(nil), "")
        XCTAssertEqual(StreamCommand.leftOut(["ES_EVENT_TYPE_NOTIFY_CLOSE": 0]), "")
        XCTAssertEqual(StreamCommand.leftOut(["ES_EVENT_TYPE_NOTIFY_CLOSE": 1]), ", left out 1 unmodified close")
        XCTAssertEqual(StreamCommand.leftOut(["ES_EVENT_TYPE_NOTIFY_OPEN": 2]), ", left out 2 open events")
    }
}
