//
//  IndicatorEngineChangeTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Saving an edit from Settings
/// Pins how Settings' editor and rows save to the Mac's set (``IndicatorEngine/change(_:from:)``): only what changed
/// from the copy they started from is sent, as a switch and an update of the fields that differ, so a change another
/// writer made meanwhile stays, and an indicator removed meanwhile isn't brought back.
final class IndicatorEngineChangeTests: XCTestCase {
    /// The Mac's set, loaded.
    private var set: SavedIndicatorSet!
    /// Each request the engine sent, in order.
    private let sent = Recorded<IndicatorRequest>()
    /// The engine, connected to the set, having listed it.
    private var engine: IndicatorEngine!

    /// A loaded set, and an engine that records each request it sends to it.
    ///
    /// - Throws: If the set's directory can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        set = try makeSavedIndicatorSet()
        set.load()
        let base = transport(to: set)
        engine = IndicatorEngine(defaults: makeDefaults()) { [sent] request, reply in
            if let decoded = try? IndicatorRequest.decode(request), decoded.operation != .list { sent.append(decoded) }
            base(request, reply)
        }
        send(IndicatorRequest(.list), through: engine)
    }

    /// Wait for every request sent so far, then list the set.
    ///
    /// - Returns: The set, as the engine now shows it.
    private func settled() -> [Indicator] {
        send(IndicatorRequest(.list), through: engine)
        return engine.indicators
    }

    /// `update` sends the fields with the indicators, and the engine shows the set the reply has.
    func testUpdateSendsTheFieldsAndShowsTheReply() throws {
        var edited = Indicator.defaults[2]
        edited.severity = edited.severity == .high ? .low : .high
        let reply = expectation(description: "Reply")
        engine.update([edited], fields: [.severity]) { XCTAssertEqual($0?.status, .ok); reply.fulfill() }
        wait(for: [reply], timeout: 10)
        XCTAssertEqual(sent.all, [IndicatorRequest(.update, indicators: [edited], fields: [.severity])])
        XCTAssertEqual(engine.indicators[2], edited)
        XCTAssertNil(engine.failure)
    }

    /// Only what changed is sent: a new indicator is added, a switch alone is a setEnabled, the view switches alone
    /// nothing, and a switch with other fields a setEnabled, then an update of those fields.
    func testOnlyWhatChangedIsSent() throws {
        let mine = ownIndicator("Mine", IndicatorCommandLineTests.curl)
        engine.change(mine, from: nil)
        let opened = Indicator.defaults[1]
        var switched = opened
        switched.isEnabled.toggle()
        engine.change(switched, from: opened)
        var viewed = opened
        viewed.tableMarks = opened.tableMarks.isEmpty ? [.dot, .symbol] : []
        engine.change(viewed, from: opened)
        var both = opened
        both.isEnabled.toggle()
        both.severity = opened.severity == .high ? .low : .high
        both.name = "Renamed"
        engine.change(both, from: opened)
        _ = settled()
        XCTAssertEqual(sent.all.map(\.operation), [.add, .setEnabled, .setEnabled, .update])
        XCTAssertEqual(sent.all[2].enabled, !opened.isEnabled)
        XCTAssertEqual(sent.all[3].fields, [.name, .severity])
        XCTAssertEqual(sent.all[3].indicators.map(\.id), [opened.id])
    }

    /// An edit that only re-spells a constant, NFC to NFD (``CanonicalSpellings``), which Swift's `==` takes as no
    /// change, is sent as an update of the predicate, and the engine shows the set with the new spelling.
    func testReSpellingAConstantIsSentAndShown() throws {
        let pair = try XCTUnwrap(CanonicalSpellings.pairs.first)
        engine.change(pair.composed, from: nil)
        _ = settled()
        var respelled = pair.decomposed
        respelled.id = pair.composed.id
        engine.change(respelled, from: pair.composed)
        let shown = try XCTUnwrap(settled().first { $0.id == respelled.id })
        XCTAssertEqual(sent.all.map(\.operation), [.add, .update])
        XCTAssertEqual(sent.all.last?.fields, [.predicate])
        XCTAssertEqual(Array(shown.predicate.utf8), Array(respelled.predicate.utf8))
    }

    /// An indicator another writer turned off while the editor had it open stays off when the editor, which still
    /// has it on, saves a new severity. The severity is saved.
    func testAnEditKeepsAnotherWritersSwitch() throws {
        let opened = try XCTUnwrap(engine.indicators.first { $0.isEnabled })
        XCTAssertEqual(set.send(IndicatorRequest(.setEnabled, ids: [opened.id], enabled: false)).status, .ok)
        var edited = opened
        edited.severity = opened.severity == .high ? .low : .high
        engine.change(edited, from: opened)
        let after = try XCTUnwrap(settled().first { $0.id == opened.id })
        XCTAssertFalse(after.isEnabled)
        XCTAssertEqual(after.severity, edited.severity)
        XCTAssertNil(engine.failure)
    }

    /// An indicator another writer removed while the editor had it open isn't brought back by saving the editor:
    /// the Security Extension refuses the update, and Settings says why.
    func testAnEditOfARemovedIndicatorIsRefused() throws {
        let opened = Indicator.defaults[0]
        XCTAssertEqual(set.send(IndicatorRequest(.remove, ids: [opened.id])).status, .ok)
        var edited = opened
        edited.predicate += " AND process.pid > 1"
        engine.change(edited, from: opened)
        XCTAssertFalse(settled().contains { $0.id == opened.id })
        XCTAssertEqual(engine.failure, "No indicator has the identity \(opened.id.uuidString).")
    }

    /// An editor opened on an indicator the set has is never an add, even once another writer removed it: its save
    /// is refused as an update, and the indicator stays removed. One opened by Add Indicator is an add.
    func testAnEditorOpenedOnAnIndicatorNeverAddsIt() throws {
        let opened = IndicatorEditing.existing(Indicator.defaults[0])
        XCTAssertFalse(opened.isNew)
        XCTAssertEqual(opened.original, Indicator.defaults[0])
        XCTAssertEqual(set.send(IndicatorRequest(.remove, ids: [opened.id])).status, .ok)
        XCTAssertFalse(settled().contains { $0.id == opened.id })
        var edited = opened.indicator
        edited.severity = edited.severity == .high ? .low : .high
        engine.change(edited, from: opened.original)
        let added = IndicatorEditing.new(ownIndicator("Mine", IndicatorCommandLineTests.curl))
        XCTAssertTrue(added.isNew)
        engine.change(added.indicator, from: added.original)
        let after = settled()
        XCTAssertEqual(sent.all.map(\.operation), [.update, .add])
        XCTAssertFalse(after.contains { $0.id == opened.id })
        XCTAssertTrue(after.contains { $0.id == added.id })
    }
}
