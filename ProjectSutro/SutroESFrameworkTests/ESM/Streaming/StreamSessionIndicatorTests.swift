//
//  StreamSessionIndicatorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import os
@testable import SutroESFramework


// MARK: - The indicator set over a stream's connection
/// Pins the Mac's indicator set as `macmonitor` reaches it over a real NSXPC connection: every stream follows it,
/// `--no-mutes` too, so one `macmonitor`'s change reaches every running stream from its next event, and who may list
/// or change it without root is the level Settings sets, as for mutes.
final class StreamSessionIndicatorTests: XCTestCase {
    /// Every close.
    private static let everyClose = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_CLOSE""#

    /// A stream of closes.
    ///
    /// - Parameter mutes: Apply the saved mutes?
    /// - Returns: The request's JSON.
    private func streamCloses(mutes: Bool) -> Data {
        StreamRequest(.stream, options: StreamOptions(events: ["ES_EVENT_TYPE_NOTIFY_CLOSE"],
                                                      appliesSavedMutes: mutes)).encoded()
    }

    /// The hits' names of the events a reader received.
    ///
    /// - Parameter reader: The reader.
    /// - Returns: Each event's, in order.
    /// - Throws: The error decoding an event.
    private func hitNames(_ reader: TestStreamReader) throws -> [[String]] {
        try reader.events.map {
            try JSONDecoder().decode(Message.self, from: Data($0.utf8)).indicators?.hits.map(\.name) ?? []
        }
    }

    /// One `macmonitor`'s add reaches every running stream, `--no-mutes` included, from its next event, and the
    /// set's file has it. The set's own followers have it too, as Mac Monitor's capture does.
    func testAChangeReachesEveryStream() throws {
        let savedIndicators = try makeSavedIndicatorSet()
        let harness = StreamHarness(savedMutes: SavedMuteSet(testing: try makeMuteStore()),
                                    serializer: MessageSerializer(processPath: { _, _ in nil }),
                                    savedIndicators: savedIndicators)
        let readers = [TestStreamReader(), TestStreamReader()]
        let connections = readers.map { harness.connect(reader: $0) }
        defer { connections.forEach { $0.invalidate() } }
        XCTAssertEqual(connections[0].send(streamCloses(mutes: true))?.status, .ok)
        XCTAssertEqual(connections[1].send(streamCloses(mutes: false))?.status, .ok)
        let app = Recorded<CompiledIndicators>()
        let following = savedIndicators.follow { app.append($0) }.1
        defer { following.cancel() }

        let own = ownIndicator("Any close", Self.everyClose, severity: .low)
        let reply = try XCTUnwrap(connections[1].sendIndicators(IndicatorRequest(.add, indicators: [own])))
        XCTAssertEqual(reply.status, .ok)
        XCTAssertEqual(reply.access, .write)
        XCTAssertEqual(reply.indicators.last, own)
        XCTAssertTrue(waitUntil { app.all.count == 1 })
        XCTAssertTrue(app.all.first === savedIndicators.current)

        /// Each stream's change was queued on its session's queue before the reply, so a hello answered after it
        /// means the stream has it.
        for connection in connections {
            XCTAssertEqual(connection.send(StreamRequest(.hello).encoded())?.status, .ok)
        }
        for (index, factory) in harness.factories.enumerated() {
            factory.client(.file).deliver(closeMessage(modified: false, path: "/tmp/f", global: UInt64(index + 1)))
        }
        XCTAssertTrue(waitUntil { readers.allSatisfy { $0.events.count == 1 } })
        for reader in readers {
            XCTAssertEqual(try hitNames(reader), [["Any close"]])
        }
    }

    /// A caller the service doesn't admit (not root) is refused, and a service without a set says so.
    func testRefusalsOverTheConnection() throws {
        let refusing = StreamHarness(savedMutes: SavedMuteSet(testing: try makeMuteStore()), admits: false,
                                     savedIndicators: try makeSavedIndicatorSet())
        let refused = refusing.connect(reader: TestStreamReader())
        defer { refused.invalidate() }
        let answer = refused.sendIndicators(IndicatorRequest(.list))
        XCTAssertEqual(answer?.status, .refused)
        XCTAssertEqual(answer?.failure, CommandLineAccess.needsRoot)

        let bare = StreamHarness(savedMutes: SavedMuteSet(testing: try makeMuteStore()))
        let connection = bare.connect(reader: TestStreamReader())
        defer { connection.invalidate() }
        XCTAssertEqual(connection.sendIndicators(IndicatorRequest(.list))?.status, .storageFailed)
    }

    /// Without root, the live rule decides each request by the level as it stands: refused at the default, listing
    /// but not changing once streaming is allowed, and changing too once changes are. Each reply says what the
    /// caller may do, and the refusals say why.
    func testACallerWithoutRootGetsWhatTheLevelAllows() throws {
        try XCTSkipIf(geteuid() == 0, "The test process is root, which may always do everything.")
        let level = OSAllocatedUnfairLock(initialState: CommandLineAccess.rootOnly)
        let harness = StreamHarness(savedMutes: SavedMuteSet(testing: try makeMuteStore()),
                                    admitting: StreamService.granting { level.withLock { $0 } },
                                    savedIndicators: try makeSavedIndicatorSet())
        let connection = harness.connect(reader: TestStreamReader())
        defer { connection.invalidate() }
        let add = IndicatorRequest(.add, indicators: [ownIndicator("Any close", Self.everyClose)])
        XCTAssertEqual(connection.sendIndicators(IndicatorRequest(.list))?.failure, CommandLineAccess.needsRoot)

        level.withLock { $0 = .streaming }
        let listed = connection.sendIndicators(IndicatorRequest(.list))
        XCTAssertEqual(listed?.status, .ok)
        XCTAssertEqual(listed?.access, .list)
        XCTAssertEqual(listed?.indicators, Indicator.defaults)
        let changing = connection.sendIndicators(add)
        XCTAssertEqual(changing?.status, .refused)
        XCTAssertEqual(changing?.failure, CommandLineAccess.needsChanges)

        level.withLock { $0 = .streamingAndChanges }
        let changed = connection.sendIndicators(add)
        XCTAssertEqual(changed?.status, .ok)
        XCTAssertEqual(changed?.access, .write)
        XCTAssertEqual(changed?.indicators.last?.name, "Any close")
    }
}
