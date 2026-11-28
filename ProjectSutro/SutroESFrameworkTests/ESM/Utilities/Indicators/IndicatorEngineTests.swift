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
/// it can't. It's read-only with "Update the Security Extension" when a request gets no reply, as from one older
/// than 3.1, and read-only while another Mac Monitor owns the stream or a newer one saved the set. Each change is
/// made as a request, with why the Security Extension can't run an indicator.
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

    /// The set is listed again after every change anyone posts, so a list that finds it as it was tells no view
    /// watching the engine. One that finds a change does.
    func testAListThatChangesNothingTellsNoView() throws {
        let set = try loadedSet()
        let engine = IndicatorEngine(defaults: makeDefaults(), transport: transport(to: set))
        send(IndicatorRequest(.list), through: engine)
        var told = 0
        let watching = engine.objectWillChange.sink { _ in told += 1 }
        defer { watching.cancel() }

        send(IndicatorRequest(.list), through: engine)
        XCTAssertEqual(told, 0, "Nothing changed")

        set.send(IndicatorRequest(.add, indicators: [ownIndicator("Mine", Self.exec)]))
        send(IndicatorRequest(.list), through: engine)
        XCTAssertGreaterThan(told, 0, "The set changed")
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

    /// Each change is a request whose reply shows the set after it: an add, turning one off, removing one, and
    /// Restore Defaults, after which the set is the shipped one again, whatever its view switches. An add of one the
    /// Security Extension can't run is refused, and says why.
    func testChangesShowTheSetAfterThem() throws {
        let engine = IndicatorEngine(defaults: makeDefaults(), transport: transport(to: try loadedSet()))
        send(IndicatorRequest(.list), through: engine)
        XCTAssertTrue(engine.isDefault)

        let untyped = ownIndicator("Untyped", #"process.executable.path == "/bin/sh""#)
        let reason = try XCTUnwrap(untyped.sensorProblem)
        XCTAssertNil(untyped.problem)
        engine.add([untyped])
        send(IndicatorRequest(.list), through: engine)
        XCTAssertEqual(engine.failure, "“Untyped” can't run in the Security Extension. \(reason)")
        XCTAssertTrue(engine.isDefault)
        engine.failure = nil
        let mine = ownIndicator("Mine", #"event.exec != nil AND process.executable.path == "/bin/sh""#)
        engine.add([mine])
        send(IndicatorRequest(.list), through: engine)
        XCTAssertEqual(engine.indicators.last?.id, mine.id)
        XCTAssertEqual(engine.problems, [:])
        XCTAssertFalse(engine.isDefault)

        let first = try XCTUnwrap(Indicator.defaults.first)
        engine.setEnabled([first.id], false)
        send(IndicatorRequest(.list), through: engine)
        XCTAssertEqual(engine.indicators.first?.isEnabled, false)

        engine.remove([mine.id])
        send(IndicatorRequest(.list), through: engine)
        XCTAssertFalse(engine.indicators.contains { $0.id == mine.id })

        engine.restoreDefaults()
        send(IndicatorRequest(.list), through: engine)
        XCTAssertEqual(engine.indicators, Indicator.defaults)
        XCTAssertNil(engine.failure)

        var viewed = Indicator.defaults
        viewed[0].tableMarks = []
        send(IndicatorRequest(.replace, indicators: viewed), through: engine)
        XCTAssertTrue(engine.isDefault, "View switches aren't the indicator")
    }

    /// Mac Monitor's own indicators are the Security Extension's, not this app's: once a pack is installed, the set
    /// that equals the pack's is the default one, and Restore Defaults brings the pack's back.
    func testAnInstalledPacksIndicatorsAreTheDefaults() throws {
        let set = try makeSavedIndicatorSet(defaults: try linkedFixtures(), verifier: try packVerifier())
        set.load()
        let engine = IndicatorEngine(defaults: makeDefaults(), transport: transport(to: set))
        XCTAssertEqual(engine.baseline, Indicator.defaults, "This build's, until the Security Extension says")
        XCTAssertNil(engine.pack)
        send(IndicatorRequest(.list), through: engine)
        XCTAssertEqual(engine.baseline, try linkedFixtures())
        XCTAssertEqual(engine.pack, IndicatorPackStatus(sequence: 0, source: .linked, mode: .notify))
        XCTAssertTrue(engine.isDefault)

        let (file, pack) = try releaseFixture(2)
        XCTAssertEqual(send(IndicatorRequest(.installPack, pack: file), through: engine)?.status, .ok)
        XCTAssertNil(engine.failure)
        XCTAssertEqual(engine.indicators, pack.indicators)
        XCTAssertEqual(engine.baseline, pack.indicators)
        XCTAssertEqual(engine.pack?.sequence, 2)
        XCTAssertEqual(engine.pack?.source, .installed)
        XCTAssertTrue(engine.isDefault)

        engine.remove([pack.indicators[0].id])
        send(IndicatorRequest(.list), through: engine)
        XCTAssertFalse(engine.isDefault)
        engine.restoreDefaults()
        send(IndicatorRequest(.list), through: engine)
        XCTAssertEqual(engine.indicators, pack.indicators)
        XCTAssertTrue(engine.isDefault)

        let refused = send(IndicatorRequest(.installPack, pack: file), through: engine)
        XCTAssertEqual(refused?.status, .invalid)
        XCTAssertEqual(refused?.failure, "Pack 2 is already installed.")
        XCTAssertNil(engine.failure, "An install says how it went where it was asked for")
    }

    /// The hits Mac Monitor matches itself, for an event with no stored verdicts, say what the Security Extension's
    /// say: an indicator only the installed pack has is one of Mac Monitor's own, as the engine last heard.
    func testTheBaselineIsKeptForMacMonitorsOwnMatching() throws {
        let defaults = makeDefaults()
        XCTAssertEqual(IndicatorEngine.cachedBaseline(in: defaults), Indicator.defaults, "None kept yet")
        let set = try makeSavedIndicatorSet(defaults: try linkedFixtures(), verifier: try packVerifier())
        set.load()
        let engine = IndicatorEngine(defaults: defaults, transport: transport(to: set))
        let (file, pack) = try releaseFixture(2)
        XCTAssertEqual(send(IndicatorRequest(.installPack, pack: file), through: engine)?.status, .ok)
        XCTAssertEqual(IndicatorEngine.cachedBaseline(in: defaults), pack.indicators)

        let added = pack.indicators[2]
        let hit = IndicatorHit(added, against: Indicator.byID(IndicatorEngine.cachedBaseline(in: defaults)),
                               evaluatedBy: .export)
        XCTAssertTrue(hit.isDefault)
        XCTAssertFalse(IndicatorHit(added, against: CompiledIndicators.shippedDefaults, evaluatedBy: .export).isDefault,
                       "This build's own don't have it")
    }

    /// A cache that can't be read is Mac Monitor's own indicators.
    func testAnUnreadableCacheIsTheShippedSet() {
        let defaults = makeDefaults()
        defaults.set(Data("not indicators".utf8), forKey: IndicatorEngine.cacheKey)
        XCTAssertEqual(IndicatorEngine.cachedIndicators(in: defaults), Indicator.defaults)
        XCTAssertEqual(IndicatorEngine(defaults: defaults).indicators, Indicator.defaults)
    }
}
