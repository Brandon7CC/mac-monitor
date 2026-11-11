//
//  SavedIndicatorSetUpdateTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Updating indicators in the Mac's set
/// Pins `update`, how an edit reaches the Security Extension: only the fields named change, in the indicator's place,
/// so another writer's switch survives and a removed indicator is never brought back. It also pins what's refused and
/// why, what it compiles, how a shipped indicator it changes is saved, and that each hit says whether this Mac edited
/// it.
final class SavedIndicatorSetUpdateTests: XCTestCase {
    /// Every exec.
    private static let exec = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#

    /// The test's directory.
    private var directory: URL!
    /// A loaded set in it.
    private var set: SavedIndicatorSet!

    /// A loaded set in a fresh directory for each test.
    ///
    /// - Throws: If the directory can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        directory = try makeIndicatorDirectory()
        set = try makeSavedIndicatorSet(in: directory)
        set.load()
    }

    /// The fourth shipped indicator, which a test edits.
    private var target: Indicator { Indicator.defaults[3] }

    /// The saved file's entries, as JSON objects.
    ///
    /// - Returns: The entries.
    /// - Throws: A failure when there's no file, or it isn't an indicator file.
    private func savedEntries() throws -> [[String: Any]] {
        let data = try XCTUnwrap(indicatorFile(in: directory))
        let file = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        return try XCTUnwrap((file["saved"] as? [String: Any])?["entries"] as? [[String: Any]])
    }

    /// An update takes only the fields it names, into the indicator in its place: its identity, switch and views,
    /// and every other field, stay as the set has them. It's saved.
    func testUpdateChangesOnlyTheNamedFields() throws {
        var edited = target
        edited.name = "Renamed"
        edited.severity = target.severity == .high ? .low : .high
        edited.predicate = Self.exec + " AND process.pid > 1"
        edited.isEnabled.toggle()
        edited.tableMarks = target.tableMarks.isEmpty ? [.dot, .symbol] : []
        let reply = set.send(IndicatorRequest(.update, indicators: [edited], fields: [.predicate, .severity]))
        XCTAssertEqual(reply.status, .ok)
        XCTAssertTrue(reply.changed)
        var expected = target
        expected.predicate = edited.predicate
        expected.severity = edited.severity
        XCTAssertEqual(reply.indicators[3], expected)
        XCTAssertEqual(reply.indicators.map(\.id), Indicator.defaults.map(\.id))
        XCTAssertEqual(try savedIndicators(in: directory)[3], expected)
    }

    /// An update of an identity the set doesn't have, as one removed since the editor opened, is invalid and adds
    /// nothing, where an add would have brought it back.
    func testUpdateOfAnUnknownIdentityIsInvalidAndAddsNothing() throws {
        XCTAssertEqual(set.send(IndicatorRequest(.remove, ids: [target.id])).status, .ok)
        let before = indicatorFile(in: directory)
        var edited = target
        edited.severity = .high
        let reply = set.send(IndicatorRequest(.update, indicators: [edited], fields: [.severity]))
        XCTAssertEqual(reply.status, .invalid)
        XCTAssertEqual(reply.failure, "No indicator has the identity \(target.id.uuidString).")
        XCTAssertFalse(reply.indicators.contains { $0.id == target.id })
        XCTAssertEqual(indicatorFile(in: directory), before)
    }

    /// An indicator another writer turned off while an editor had it open stays off when the editor's copy, still
    /// on, is saved as an update.
    func testAConcurrentDisableSurvivesAnUpdate() throws {
        let opened = try XCTUnwrap(Indicator.defaults.first { $0.isEnabled })
        XCTAssertEqual(set.send(IndicatorRequest(.setEnabled, ids: [opened.id], enabled: false)).status, .ok)
        var edited = opened
        edited.severity = opened.severity == .high ? .low : .high
        let reply = set.send(IndicatorRequest(.update, indicators: [edited],
                                              fields: opened.changedFields(to: edited)))
        let after = try XCTUnwrap(reply.indicators.first { $0.id == opened.id })
        XCTAssertFalse(after.isEnabled)
        XCTAssertEqual(after.severity, edited.severity)
        XCTAssertEqual(set.send(IndicatorRequest(.add, indicators: [edited])).indicators
            .first { $0.id == opened.id }?.isEnabled, true, "An add, by contrast, takes the whole copy")
    }

    /// An update to what the indicator already has is answered without a save.
    func testANoOpUpdateSavesNothing() throws {
        let path = directory.appendingPathComponent(IndicatorFile.layout.fileName).path
        let before = try FileManager.default.attributesOfItem(atPath: path)[.systemFileNumber] as? Int
        var same = target
        same.isEnabled.toggle()
        let reply = set.send(IndicatorRequest(.update, indicators: [same], fields: [.name, .severity]))
        XCTAssertEqual(reply.status, .ok)
        XCTAssertFalse(reply.changed)
        let after = try FileManager.default.attributesOfItem(atPath: path)[.systemFileNumber] as? Int
        XCTAssertEqual(before, after, "A save replaces the file")
        XCTAssertEqual(reply.indicators, Indicator.defaults)
    }

    /// A severity or name update compiles nothing. A predicate update compiles only its new predicate. The compiled
    /// hits carry the update.
    func testUpdateCompilesOnlyTheNewPredicate() throws {
        var edited = target
        edited.severity = target.severity == .high ? .low : .high
        edited.name = "Renamed"
        set.send(IndicatorRequest(.update, indicators: [edited], fields: [.name, .severity]))
        XCTAssertEqual(set.current.compiledCount, 0)
        let hit = try XCTUnwrap(set.current.ruleHits.first { $0.id == target.id })
        XCTAssertEqual([hit.name, hit.severity.rawValue], ["Renamed", edited.severity.rawValue])
        edited.predicate = Self.exec + " AND process.pid > 1"
        set.send(IndicatorRequest(.update, indicators: [edited], fields: [.predicate]))
        XCTAssertEqual(set.current.compiledCount, 1)
    }

    /// An update that only re-spells a constant, NFC to NFD (``CanonicalSpellings``), which Swift's `==` takes as no
    /// change, is one: it's saved as spelled, and the set compiled with it, so `==`, `!=` and `IN` decide as the new
    /// spelling does. The editor sends it, too.
    func testReSpellingAConstantIsAChange() throws {
        var message = try XCTUnwrap(SyntheticCorpus.records().map(\.message)
            .first { $0.es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" })
        message.target_path = CanonicalSpellings.nfd
        func hits(_ id: UUID) -> Bool {
            var values = MessageValueCache()
            return set.current.hits(for: message, values: &values).contains { $0.id == id }
        }
        for pair in CanonicalSpellings.pairs {
            let id = pair.composed.id
            var respelled = pair.decomposed
            respelled.id = id
            XCTAssertEqual(pair.composed, respelled, pair.format)
            XCTAssertEqual(pair.composed.changedFields(to: respelled), [.predicate], pair.format)
            XCTAssertEqual(set.send(IndicatorRequest(.add, indicators: [pair.composed])).status, .ok, pair.format)
            XCTAssertEqual(hits(id), pair.hit == id, pair.format)

            let reply = set.send(IndicatorRequest(.update, indicators: [respelled], fields: [.predicate]))
            XCTAssertEqual(reply.status, .ok, pair.format)
            XCTAssertTrue(reply.changed, pair.format)
            let saved = try XCTUnwrap(try savedIndicators(in: directory).first { $0.id == id }, pair.format)
            XCTAssertEqual(Array(saved.predicate.utf8), Array(respelled.predicate.utf8), pair.format)
            XCTAssertEqual(hits(id), pair.hit != id, pair.format)
        }
    }

    /// An update is checked as what it makes: it needs fields, names each indicator once, and leaves no indicator
    /// with an event type this build doesn't know, nor past a limit. Each refusal changes nothing.
    func testUpdateIsCheckedAsTheResult() throws {
        let before = indicatorFile(in: directory)
        var unknownType = target
        unknownType.predicate = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_NOPE""#
        let refusals: [(IndicatorRequest, String?)] = [
            (IndicatorRequest(.update, indicators: [target]), "Name the fields to change."),
            (IndicatorRequest(.update, indicators: [target, target], fields: [.name]), "Name each indicator once."),
            (IndicatorRequest(.update, fields: [.name]), "Name the indicators by their identities."),
            (IndicatorRequest(.update, indicators: [unknownType], fields: [.predicate]), nil),
        ]
        for (request, failure) in refusals {
            let reply = set.send(request)
            XCTAssertEqual(reply.status, .invalid, "\(request.fields)")
            if let failure { XCTAssertEqual(reply.failure, failure) }
            XCTAssertFalse(reply.changed)
        }
        let long = IndicatorRequest(.update, indicators: [target], fields: [.name]).encoded()
        let text = String(decoding: long, as: UTF8.self)
            .replacingOccurrences(of: "\"\(target.name)\"", with: "\"\(String(repeating: "n", count: 200))\"")
        XCTAssertEqual(set.send(Data(text.utf8)).status, .invalid)
        XCTAssertEqual(indicatorFile(in: directory), before)
    }

    /// A caller that may only read or list is refused an update, and so is everyone while the set is read-only.
    func testUpdateIsRefusedForReadersAndWhileReadOnly() throws {
        var edited = target
        edited.severity = .high
        let update = IndicatorRequest(.update, indicators: [edited], fields: [.severity])
        for access in [MuteAccess.read, .list] {
            XCTAssertEqual(set.send(update, access: access).status, .refused, access.rawValue)
        }
        let newer = try makeIndicatorDirectory()
        try writeIndicatorFile(Data(#"{"version": 2, "saved": {"entries": []}}"#.utf8), in: newer)
        let readOnly = try makeSavedIndicatorSet(in: newer)
        readOnly.load()
        XCTAssertEqual(readOnly.send(update).status, .readOnly)
        XCTAssertEqual(try savedIndicators(in: directory), Indicator.defaults)
    }

    /// A shipped indicator whose severity alone an update changed is saved as a reference with that severity, so a
    /// later build's predicate reaches it. One whose predicate it changed is saved in full, and keeps it.
    func testAShippedIndicatorFollowsLaterBuildsUnlessItsRuleChanged() throws {
        var severe = target
        severe.severity = target.severity == .high ? .low : .high
        set.send(IndicatorRequest(.update, indicators: [severe], fields: [.severity]))
        let reference = try XCTUnwrap(try savedEntries().first { $0["default"] as? String == target.id.uuidString })
        XCTAssertEqual(reference["severity"] as? String, severe.severity.rawValue)
        XCTAssertNil(reference["predicate"])

        var later = Indicator.defaults
        later[3].predicate += " AND process.pid > 0"
        XCTAssertEqual(try savedIndicators(in: directory, defaults: later)[3].predicate, later[3].predicate)
        XCTAssertEqual(try savedIndicators(in: directory, defaults: later)[3].severity, severe.severity)

        var rule = severe
        rule.predicate = Self.exec + " AND process.pid > 1"
        set.send(IndicatorRequest(.update, indicators: [rule], fields: [.predicate]))
        let full = try XCTUnwrap(try savedEntries().first { $0["id"] as? String == target.id.uuidString })
        XCTAssertEqual(full["predicate"] as? String, rule.predicate)
        XCTAssertEqual(try savedIndicators(in: directory, defaults: later)[3].predicate, rule.predicate)
    }

    /// Each compiled hit says whether this Mac edited the shipped indicator it's for: not as shipped, nor for a
    /// switch or a view, yes after any editable field changes, back to no once it's restored, and never for one of
    /// the user's own.
    func testHitsSayWhetherAShippedIndicatorWasEdited() throws {
        func edited() -> Bool? { set.current.ruleHits.first { $0.id == target.id }?.edited }
        XCTAssertEqual(edited(), false)
        var viewed = target
        viewed.tableMarks = target.tableMarks.isEmpty ? [.dot, .symbol] : []
        set.send(IndicatorRequest(.add, indicators: [viewed]))
        XCTAssertEqual(edited(), false, "Views aren't the detection")
        var technique = target
        technique.technique = "T1059.002"
        set.send(IndicatorRequest(.update, indicators: [technique], fields: [.technique]))
        XCTAssertEqual(edited(), true)
        set.send(IndicatorRequest(.update, indicators: [target], fields: [.technique]))
        XCTAssertEqual(edited(), false, "Restored")
        let own = ownIndicator("Mine", Self.exec)
        set.send(IndicatorRequest(.add, indicators: [own]))
        XCTAssertEqual(set.current.ruleHits.first { $0.id == own.id }.map { [$0.isDefault, $0.edited] }, [false, false])
    }
}
