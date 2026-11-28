//
//  StreamSessionHoldTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/26/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Mac Monitor's serializer for closes alone
/// Mac Monitor's serializer for closes, so a written file's close is scanned and held, and any other event's
/// `global_seq_num` as its JSON, so thousands of them cost little.
private struct ScannedClosesSerializer: EventSerializing {
    /// Serialize a close as Mac Monitor does, and any other event as ``StubSerializer/globalSequence`` does.
    ///
    /// - Parameters:
    ///   - message: The message.
    ///   - lane: The lane's context.
    /// - Returns: The close's event, or the other event's JSON.
    func serializeEvent(_ message: UnsafePointer<es_message_t>, in lane: LaneContext) -> SerializedEvent? {
        guard message.pointee.event_type == ES_EVENT_TYPE_NOTIFY_CLOSE else {
            return StubSerializer.globalSequence.serializeEvent(message, in: lane)
        }
        return MessageSerializer().serializeEvent(message, in: lane)
    }
}


// MARK: - A stream's holds
/// Pins that what a stream's lanes hold for their scans never overflows the stream's batcher, which drops events and
/// pauses capture past what it takes at once (``EventBatcher/Limits-swift.struct/commandLine``).
final class StreamSessionHoldTests: XCTestCase {
    /// A close held for its scan, with more events behind it than the batcher takes at once: the line is cut short
    /// and the close leaves as busy, so the stream drops nothing and never pauses. A hold that sent its whole line
    /// at once, as Mac Monitor's 4,096 events, dropped what didn't fit and paused capture on an idle stream.
    func testAHeldLineNeverOverflowsTheStream() throws {
        let gate = DispatchSemaphore(value: 0)
        defer { gate.signal() }
        let harness = StreamHarness(savedMutes: SavedMuteSet(testing: try makeMuteStore()),
                                    serializer: ScannedClosesSerializer(), scanner: try makeScanner(gate: gate))
        let reader = TestStreamReader()
        let connection = harness.connect(reader: reader)
        defer { connection.invalidate() }
        let options = StreamOptions(events: ["ES_EVENT_TYPE_NOTIFY_CLOSE", "ES_EVENT_TYPE_NOTIFY_OPEN"],
                                    appliesSavedMutes: false, scansWrittenFiles: true)
        XCTAssertEqual(connection.send(StreamRequest(.stream, options: options).encoded())?.status, .ok)
        let file = try XCTUnwrap(harness.factories.first).client(.file)
        let limits = EventBatcher.Limits.commandLine
        let behind = limits.maxBatchesInFlight * limits.batchSize + limits.memoryLimit + 50
        let tool = try temporaryFile(bytes: FileTypeSamples.machO(MH_EXECUTE), named: "tool")
        file.deliver(try fileClose(of: tool, global: 1))
        /// Paced well inside the hold's half second, so a reader that replies keeps up with what isn't held.
        for chunk in stride(from: 2, through: behind + 1, by: 250) {
            for global in chunk..<min(chunk + 250, behind + 2) {
                file.deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_OPEN, global: UInt64(global)))
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
        gate.signal()
        XCTAssertTrue(waitUntil(timeout: 20) { reader.events.count == behind + 1 }, "\(reader.events.count) events")
        let summary = try XCTUnwrap(connection.send(StreamRequest(.stop).encoded())?.summary)
        XCTAssertEqual(summary.pauses, 0)
        XCTAssertEqual(summary.droppedWhileBehind, 0)
        XCTAssertEqual(summary.delivered, behind + 1)
        let close = try JSONDecoder().decode(Message.self, from: Data(try XCTUnwrap(reader.events.first).utf8))
        guard case .close(let event) = close.event else { return XCTFail("Not the close") }
        XCTAssertEqual(event.yara_scan?.status, YaraScan.busy)
    }
}
