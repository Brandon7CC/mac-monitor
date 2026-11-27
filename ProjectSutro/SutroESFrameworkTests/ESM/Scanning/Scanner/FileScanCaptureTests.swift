//
//  FileScanCaptureTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Scanning as a session captures
/// Pins scanning end to end on fake clients: a modified close of a written Mach-O or script leaves its file lane with
/// `yara_scan`, events behind it keep their order, a rename that moves it gets the same result, other files and
/// unmodified closes get none, a scan that doesn't finish in time leaves as busy, and the scanner is held only while
/// the session subscribes to closes. Stand-in rules, compiled here, find a marker.
final class FileScanCaptureTests: XCTestCase {
    /// The marker the stand-in rule finds.
    private static let marker = Array("mac-monitor-scan-marker".utf8)

    /// A scanner with the stand-in rule, loaded once a `gate` lets it.
    private func markerScanner(gate: DispatchSemaphore? = nil) throws -> FileScanner {
        let library = try scannerLibrary()
        let rules = try XCTUnwrap(YaraCompiler.compile("""
        rule Marker { meta: description = "TEST.MARKER" strings: $a = "mac-monitor-scan-marker" condition: $a }
        """, with: library).rules)
        let loaded = XProtectRules(version: "5377", sets: [.xprotect: rules], problems: [:])
        return FileScanner(generation: .yara4, currentVersion: { "5377" }, load: {
            gate?.wait()
            return .success(loaded)
        })
    }

    /// A rename of a real file to a new path, with the source's stat from before the rename.
    private func rename(_ path: String, to destination: String, global: UInt64) throws -> RawMessageFixture {
        let info = try fileStat(path)
        XCTAssertEqual(Darwin.rename(path, destination), 0)
        let fixture = sequencedMessage(ES_EVENT_TYPE_NOTIFY_RENAME, global: global)
        fixture.message.pointee.event.rename.source = fixture.file(path)
        fixture.message.pointee.event.rename.source.pointee.stat = info
        fixture.message.pointee.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH
        let directory = (destination as NSString).deletingLastPathComponent
        fixture.message.pointee.event.rename.destination.new_path.dir = fixture.file(directory)
        fixture.message.pointee.event.rename.destination.new_path.filename =
            fixture.token((destination as NSString).lastPathComponent)
        return fixture
    }

    /// The messages the file lane emitted, once there are `count`.
    private func fileEvents(_ emitted: EmittedEvents, count: Int) throws -> [Message] {
        XCTAssertTrue(waitUntil { emitted.all.filter { $0.eventClass == .file }.count >= count })
        return try emitted.all.filter { $0.eventClass == .file }.map {
            try JSONDecoder().decode(Message.self, from: $0.json)
        }
    }

    /// The scan on a close or rename.
    private func scan(of message: Message) -> YaraScan? {
        switch message.event {
        case .close(let close): return close.yara_scan
        case .rename(let rename): return rename.yara_scan
        default: return nil
        }
    }

    /// A written executable's close leaves with what its scan found, the file lane's events behind it after it, and
    /// a close of a file that isn't scanned, or an unmodified one, with none.
    func testAWrittenExecutableIsScannedInOrder() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let emitted = EmittedEvents()
        let session = try scanningSession(factory, scanner: try markerScanner(), emitted: emitted)
        defer { session.stop() }
        let tool = try temporaryFile(bytes: FileTypeSamples.machO(MH_EXECUTE) + Self.marker, named: "tool")
        let clean = try temporaryFile(bytes: FileTypeSamples.machO(MH_EXECUTE), named: "clean")
        let notes = try temporaryFile(bytes: Array("mac-monitor-scan-marker".utf8), named: "notes.txt")
        let file = factory.client(.file)
        file.deliver(try fileClose(of: tool, global: 1))
        file.deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_OPEN, global: 2).withOpenFile(tool))
        file.deliver(try fileClose(of: clean, global: 3))
        file.deliver(try fileClose(of: notes, global: 4))
        file.deliver(try fileClose(of: tool, global: 5, modified: false))

        let events = try fileEvents(emitted, count: 5)
        XCTAssertEqual(events.map(\.global_seq_num), [1, 2, 3, 4, 5])
        let found = try XCTUnwrap(scan(of: events[0]))
        XCTAssertEqual(found.status, YaraScan.scanned)
        XCTAssertEqual(found.rules, ["Marker"])
        XCTAssertEqual(found.names, ["TEST.MARKER"])
        XCTAssertEqual(found.xprotect_version, "5377")
        XCTAssertEqual(scan(of: events[2]), YaraScan(status: YaraScan.scanned, xprotectVersion: "5377"))
        XCTAssertNil(scan(of: events[3]), "Plain text isn't scanned.")
        XCTAssertNil(scan(of: events[4]), "An unmodified close isn't read.")
    }

    /// A rename that moves a scanned file gets its close's result without a second scan.
    func testARenameFollowsItsClose() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let emitted = EmittedEvents()
        let session = try scanningSession(factory, scanner: try markerScanner(), emitted: emitted)
        defer { session.stop() }
        let temporary = try temporaryFile(bytes: FileTypeSamples.machO(MH_DYLIB) + Self.marker, named: ".lib.tmp")
        let destination = (temporary as NSString).deletingLastPathComponent + "/libscanned.dylib"
        let file = factory.client(.file)
        file.deliver(try fileClose(of: temporary, global: 1))
        file.deliver(try rename(temporary, to: destination, global: 2))
        let events = try fileEvents(emitted, count: 2)
        XCTAssertEqual(scan(of: events[0])?.rules, ["Marker"])
        XCTAssertEqual(scan(of: events[1])?.rules, ["Marker"])
    }

    /// A scan that can't finish within the hold's wait leaves as busy, and the events behind it are sent after it.
    func testASlowScanLeavesAsBusy() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let emitted = EmittedEvents()
        let gate = DispatchSemaphore(value: 0)
        defer { gate.signal() }
        let session = try scanningSession(factory, scanner: try markerScanner(gate: gate), emitted: emitted)
        defer { session.stop() }
        let tool = try temporaryFile(bytes: FileTypeSamples.machO(MH_EXECUTE) + Self.marker, named: "slow")
        factory.client(.file).deliver(try fileClose(of: tool, global: 1))
        factory.client(.file).deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_OPEN, global: 2).withOpenFile(tool))
        let start = Date()
        let events = try fileEvents(emitted, count: 2)
        XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(start), EventHold.defaultMaxWait * 0.8)
        XCTAssertEqual(events.map(\.global_seq_num), [1, 2])
        XCTAssertEqual(scan(of: events[0])?.status, YaraScan.busy)
    }

    /// The scanner is acquired only while the session subscribes to closes, and released when it stops.
    func testTheScannerFollowsTheCloseSubscription() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let scanner = try markerScanner()
        let session = try scanningSession(factory, scanner: scanner, events: [ES_EVENT_TYPE_NOTIFY_OPEN],
                                          emitted: EmittedEvents())
        XCTAssertFalse(scanner.isInUse)
        XCTAssertTrue(session.setSubscription(ES_EVENT_TYPE_NOTIFY_CLOSE, enabled: true))
        XCTAssertTrue(scanner.isInUse)
        XCTAssertTrue(session.setSubscription(ES_EVENT_TYPE_NOTIFY_CLOSE, enabled: false))
        XCTAssertFalse(scanner.isInUse)
        XCTAssertTrue(session.setSubscription(ES_EVENT_TYPE_NOTIFY_CLOSE, enabled: true))
        session.stop()
        XCTAssertFalse(scanner.isInUse)
    }

    /// A rule on what a scan found matches the close once its scan is done: the close is stamped again as it leaves
    /// the hold, and its hit lists the rule that matched. A set that reads no scan isn't evaluated again.
    func testARuleOnTheScanMatches() throws {
        let rule = ownIndicator("XProtect rule matched", Self.yaraRulePredicate)
        let indicators = CompiledIndicators([rule])
        XCTAssertTrue(indicators.problems.isEmpty, "\(indicators.problems.map(\.reason))")
        XCTAssertTrue(indicators.readsYaraScan)
        XCTAssertFalse(CompiledIndicators([ownIndicator("Any close", "event.close != nil")]).readsYaraScan)
        let factory = FakeEndpointSecurityClientFactory()
        let emitted = EmittedEvents()
        let session = try scanningSession(factory, scanner: try markerScanner(), indicators: indicators,
                                          emitted: emitted)
        defer { session.stop() }
        let tool = try temporaryFile(bytes: FileTypeSamples.machO(MH_EXECUTE) + Self.marker, named: "tool")
        let clean = try temporaryFile(bytes: FileTypeSamples.machO(MH_EXECUTE), named: "clean")
        factory.client(.file).deliver(try fileClose(of: tool, global: 1))
        factory.client(.file).deliver(try fileClose(of: clean, global: 2))
        let events = try fileEvents(emitted, count: 2)
        XCTAssertEqual(events[0].indicators?.hits.map(\.id), [rule.id])
        XCTAssertEqual(events[0].indicators?.hits.first?.matched,
                       [IndicatorMatchedField(field: "event.close.yara_scan.rules", value: .string("Marker"))])
        XCTAssertEqual(events[1].indicators?.hits.map(\.id) ?? [], [])
    }

    /// A session that can change scanning turns it on and off while it runs: closes are scanned only while it's on,
    /// and the scanner is held only then.
    func testScanningTurnsOnAndOff() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let emitted = EmittedEvents()
        let scanner = try markerScanner()
        var configuration = CaptureConfiguration(label: "Test")
        configuration.scanningCanChange = true
        let session = try CaptureSession(configuration, clients: factory, serializer: MessageSerializer(),
                                         sensorID: { "SENSOR" }, scanner: scanner, emit: emitted.append)
        session.isRecording = true
        defer { session.stop() }
        XCTAssertFalse(session.scansWrittenFiles)
        XCTAssertFalse(scanner.isInUse)
        let tool = try temporaryFile(bytes: FileTypeSamples.machO(MH_EXECUTE) + Self.marker, named: "tool")
        factory.client(.file).deliver(try fileClose(of: tool, global: 1))
        XCTAssertTrue(session.setScansWrittenFiles(true))
        XCTAssertTrue(scanner.isInUse)
        factory.client(.file).deliver(try fileClose(of: tool, global: 2))
        /// Its scan is done before scanning stops, or the release would leave it unavailable.
        XCTAssertEqual(try fileEvents(emitted, count: 2).count, 2)
        XCTAssertTrue(session.setScansWrittenFiles(false))
        XCTAssertFalse(scanner.isInUse)
        factory.client(.file).deliver(try fileClose(of: tool, global: 3))
        let events = try fileEvents(emitted, count: 3)
        XCTAssertEqual(events.map(\.global_seq_num), [1, 2, 3])
        XCTAssertEqual(events.map { scan(of: $0)?.rules }, [nil, ["Marker"], nil])
        session.stop()
        XCTAssertFalse(session.setScansWrittenFiles(true), "A stopped session can't scan.")
    }

    /// A session that doesn't scan puts no scan on any close, and holds nothing.
    func testNoScannerNoScan() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let emitted = EmittedEvents()
        let session = try scanningSession(factory, scanner: nil, emitted: emitted)
        defer { session.stop() }
        let tool = try temporaryFile(bytes: FileTypeSamples.machO(MH_EXECUTE) + Self.marker, named: "tool")
        factory.client(.file).deliver(try fileClose(of: tool, global: 1))
        XCTAssertNil(scan(of: try XCTUnwrap(try fileEvents(emitted, count: 1).first)))
        XCTAssertFalse(session.setScansWrittenFiles(true), "A session made without a scanner can't scan.")
    }
}


// MARK: - Fixtures
private extension RawMessageFixture {
    /// An open message's file, set to a path.
    ///
    /// - Parameter path: The opened file.
    /// - Returns: The fixture.
    func withOpenFile(_ path: String) -> RawMessageFixture {
        message.pointee.event.open.file = file(path)
        return self
    }
}
