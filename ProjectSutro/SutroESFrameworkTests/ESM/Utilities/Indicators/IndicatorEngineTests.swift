//
//  IndicatorEngineTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Mac Monitor's side of the Mac's indicator set
/// Pins what Settings > Indicators shows of the Mac's set: the set as the Security Extension sends it, kept for when
/// it can't; read-only with "Update the Security Extension" when a request gets no reply, as from one older than 3.1;
/// read-only while another Mac Monitor owns the stream or a newer one saved the set; and each change made as a
/// request, with why the Security Extension can't run an indicator.
final class IndicatorEngineTests: XCTestCase {
    /// Every exec.
    private static let exec = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#

    /// The Mac's set, loaded, in a fresh directory.
    ///
    /// - Returns: The set.
    /// - Throws: If its directory can't be created.
    private func loadedSet() throws -> SavedIndicatorSet {
        let set = try makeSavedIndicatorSet()
        set.load()
        return set
    }

    /// Before anything is asked, the cache shows, or the shipped indicators, and nothing may change. A list shows
    /// the Mac's set, which may then change, and the set is kept: a new engine starts from it, and a search reads it.
    func testListShowsTheMacSetAndKeepsIt() throws {
        let defaults = makeDefaults()
        let set = try loadedSet()
        let engine = IndicatorEngine(defaults: defaults, transport: transport(to: set))
        XCTAssertEqual(engine.indicators, Indicator.defaults)
        XCTAssertEqual(engine.connection, .waiting)
        XCTAssertFalse(engine.canChangeIndicators)

        XCTAssertEqual(send(IndicatorRequest(.list), through: engine)?.status, .ok)
        XCTAssertEqual(engine.connection, .connected)
        XCTAssertEqual(engine.access, .write)
        XCTAssertFalse(engine.isReadOnly)
        XCTAssertNil(engine.notice)
        XCTAssertTrue(engine.canChangeIndicators)

        let mine = ownIndicator("Mine", Self.exec, severity: .high)
        engine.add([mine])
        XCTAssertEqual(send(IndicatorRequest(.list), through: engine)?.indicators.last, mine)
        XCTAssertEqual(engine.indicators.last, mine)
        XCTAssertEqual(IndicatorEngine.cachedIndicators(in: defaults).last, mine)
        XCTAssertEqual(IndicatorEngine(defaults: defaults).indicators, engine.indicators)
    }

    /// A request with no reply, from a Security Extension older than 3.1 or none, leaves the last set showing,
    /// read-only, saying to update the Security Extension. A change says so too, and changes nothing.
    func testNoReplyIsReadOnly() throws {
        let defaults = makeDefaults()
        let mine = ownIndicator("Mine", Self.exec)
        defaults.set(try JSONEncoder().encode(Indicator.defaults + [mine]), forKey: IndicatorEngine.cacheKey)
        let engine = IndicatorEngine(defaults: defaults) { _, reply in DispatchQueue.main.async { reply(nil) } }

        XCTAssertNil(send(IndicatorRequest(.list), through: engine))
        XCTAssertEqual(engine.connection, .unavailable)
        XCTAssertFalse(engine.canChangeIndicators)
        XCTAssertEqual(engine.notice, IndicatorEngine.updateNotice)
        XCTAssertTrue(IndicatorEngine.updateNotice.contains("Update the Security Extension"))
        XCTAssertNil(engine.failure, "A list isn't a change")
        XCTAssertEqual(engine.indicators, Indicator.defaults + [mine])

        XCTAssertNil(send(IndicatorRequest(.remove, ids: [mine.id]), through: engine))
        XCTAssertEqual(engine.failure, IndicatorEngine.updateNotice)
        XCTAssertEqual(engine.indicators, Indicator.defaults + [mine])
    }

    /// Without a transport, nothing is sent and nothing changes.
    func testNothingIsSentWithoutATransport() {
        let engine = IndicatorEngine(defaults: makeDefaults())
        XCTAssertNil(send(IndicatorRequest(.list), through: engine))
        XCTAssertEqual(engine.connection, .waiting)
        XCTAssertFalse(engine.canChangeIndicators)
    }

    /// A Mac Monitor that may only read, because another owns the event stream, lists the set but can't change it:
    /// a change is refused, says why, and the set stays.
    func testReadAccessCantChange() throws {
        let engine = IndicatorEngine(defaults: makeDefaults(), transport: transport(to: try loadedSet(), access: .read))
        send(IndicatorRequest(.list), through: engine)
        XCTAssertEqual(engine.access, .read)
        XCTAssertFalse(engine.canChangeIndicators)
        let first = try XCTUnwrap(Indicator.defaults.first)
        XCTAssertEqual(send(IndicatorRequest(.setEnabled, ids: [first.id], enabled: false), through: engine)?.status,
                       .refused)
        XCTAssertNotNil(engine.failure)
        XCTAssertEqual(engine.indicators, Indicator.defaults)
    }

    /// A set a newer Mac Monitor saved is read-only from the first list, whoever asks, with the Security Extension's
    /// notice.
    func testANewerSetIsReadOnly() throws {
        let directory = try makeIndicatorDirectory()
        try writeIndicatorFile(Data(#"{"version": 2, "saved": {"entries": []}}"#.utf8), in: directory)
        let set = try makeSavedIndicatorSet(in: directory)
        set.load()
        let engine = IndicatorEngine(defaults: makeDefaults(), transport: transport(to: set))
        XCTAssertEqual(send(IndicatorRequest(.list), through: engine)?.readOnly, true)
        XCTAssertEqual(engine.access, .write)
        XCTAssertTrue(engine.isReadOnly)
        XCTAssertFalse(engine.canChangeIndicators)
        XCTAssertTrue(engine.notice?.contains("newer Mac Monitor") == true)
    }

    /// Each change is a request whose reply shows the set after it: an add, which may bring one the Security
    /// Extension can't run, with its reason; turning one off; removing one; and Restore Defaults, after which the set
    /// is the shipped one again, whatever its view switches.
    func testChangesShowTheSetAfterThem() throws {
        let engine = IndicatorEngine(defaults: makeDefaults(), transport: transport(to: try loadedSet()))
        send(IndicatorRequest(.list), through: engine)
        XCTAssertTrue(engine.isDefault)

        let untyped = ownIndicator("Untyped", #"process.executable.path == "/bin/sh""#)
        let reason = try XCTUnwrap(untyped.sensorProblem)
        XCTAssertNil(untyped.problem)
        engine.add([untyped])
        send(IndicatorRequest(.list), through: engine)
        XCTAssertEqual(engine.indicators.last?.id, untyped.id)
        XCTAssertEqual(engine.problems[untyped.id], reason)
        XCTAssertFalse(engine.isDefault)

        let first = try XCTUnwrap(Indicator.defaults.first)
        engine.setEnabled([first.id], false)
        send(IndicatorRequest(.list), through: engine)
        XCTAssertEqual(engine.indicators.first?.isEnabled, false)

        engine.remove([untyped.id])
        send(IndicatorRequest(.list), through: engine)
        XCTAssertFalse(engine.indicators.contains { $0.id == untyped.id })
        XCTAssertNil(engine.problems[untyped.id])

        engine.restoreDefaults()
        send(IndicatorRequest(.list), through: engine)
        XCTAssertEqual(engine.indicators, Indicator.defaults)
        XCTAssertNil(engine.failure)

        var viewed = Indicator.defaults
        viewed[0].tableMarks = []
        send(IndicatorRequest(.replace, indicators: viewed), through: engine)
        XCTAssertTrue(engine.isDefault, "View switches aren't the detection")
    }

    /// A cache that can't be read is Mac Monitor's own indicators.
    func testAnUnreadableCacheIsTheShippedSet() {
        let defaults = makeDefaults()
        defaults.set(Data("not indicators".utf8), forKey: IndicatorEngine.cacheKey)
        XCTAssertEqual(IndicatorEngine.cachedIndicators(in: defaults), Indicator.defaults)
        XCTAssertEqual(IndicatorEngine(defaults: defaults).indicators, Indicator.defaults)
    }
}
