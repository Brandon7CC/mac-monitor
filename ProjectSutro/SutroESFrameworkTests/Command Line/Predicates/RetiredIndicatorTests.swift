//
//  RetiredIndicatorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - osascript, dropped
/// Pins what becomes of osascript, which 3.1.0 stopped shipping because AppleScript / JXA covers it, on a Mac that had
/// it: the Mac's set drops it unless its rule was edited, when it stays as the user's own; a user's 3.0 copy is
/// offered only when edited; a user's leftover view switches and silence change
/// nothing; a trace stamped with it keeps that verdict; and its identity is never shipped again.
final class RetiredIndicatorTests: XCTestCase {
    /// Every exec.
    private static let exec = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#

    /// The identities earlier builds shipped and this one doesn't are Not quarantined's, osascript's and Non-Apple as
    /// root's. None is a shipped indicator's or a built-in mark's again, so a saved switch, silence or verdict of
    /// one never lands on another rule.
    func testDroppedIdentitiesAreNeverShippedAgain() throws {
        let dropped = Set(Indicator.retiredNumbers.map(Indicator.uuid))
        XCTAssertEqual(dropped, Set([2, 12, 14, 34, 36, 37, 38, 39].map(Indicator.uuid)))
        XCTAssertTrue(dropped.isDisjoint(with: (Indicator.defaults + Indicator.builtInMarks).map(\.id)))
        XCTAssertNil(CompiledIndicators.shippedDefaults[Self.osascriptID])
        XCTAssertFalse(Indicator.defaults.contains { $0.name == "osascript" })
        let osascript = try droppedOsascript()
        XCTAssertEqual(osascript.tactic, .execution)
        XCTAssertEqual(osascript.technique, "T1059.002")
        XCTAssertEqual(osascript.severity, .low)
    }

    /// No shipped indicator matches an exec of osascript any more, as osascript did; AppleScript / JXA matches the
    /// scripting component it maps.
    func testNoShippedIndicatorMatchesAnOsascriptExec() throws {
        let exec: NSDictionary = ["es_event_type": "ES_EVENT_TYPE_NOTIFY_EXEC", "event": ["exec": ["target": [
            "executable": ["path": "/usr/bin/osascript", "name": "osascript"], "codesigning_type": "PLATFORM",
            "signing_id": "com.apple.osascript", "is_adhoc_signed": false]]]]
        XCTAssertTrue(try StreamFilter.Predicate(droppedOsascript().predicate, for: .indicator).evaluate(on: exec))
        for indicator in Indicator.defaults {
            let predicate = try StreamFilter.Predicate(indicator.predicate, for: .indicator)
            XCTAssertFalse(try predicate.evaluate(on: exec), indicator.name)
        }
        let mmap: NSDictionary = ["es_event_type": "ES_EVENT_TYPE_NOTIFY_MMAP", "event": ["mmap": [:]],
                                  "target_path": "/System/Library/Components/AppleScript.component/Contents/MacOS/"
                                    + "AppleScript"]
        let script = try XCTUnwrap(Indicator.defaults.first { $0.name == "AppleScript / JXA" })
        XCTAssertTrue(try StreamFilter.Predicate(script.predicate, for: .indicator).evaluate(on: mmap))
    }

    /// The Security Extension loads a set the build before saved with osascript as shipped, turned off and given a
    /// severity, as this build's own indicators: osascript is gone, from the rules it runs and, after the next
    /// change, from the file.
    func testTheMacsSetDropsAnUneditedOsascript() throws {
        var osascript = try droppedOsascript()
        osascript.isEnabled = false
        osascript.severity = .medium
        let saved = try savedWithOsascript(osascript)
        XCTAssertNotNil(try osascriptEntry(in: saved)["default"], "Saved by identity, as unedited")
        let set = try loadedSet(saved)
        let reply = set.send(IndicatorRequest(.list))
        XCTAssertEqual(reply.indicators, Indicator.defaults)
        XCTAssertNil(reply.notice)
        XCTAssertNil(set.current.ruleHits.first { $0.id == Self.osascriptID })
        XCTAssertEqual(set.send(IndicatorRequest(.add, indicators: [ownIndicator("Mine", Self.exec)])).status, .ok)
        let file = try XCTUnwrap(indicatorFile(in: try XCTUnwrap(directory)))
        XCTAssertFalse(String(decoding: file, as: UTF8.self).contains(Self.osascriptID.uuidString))
    }

    /// One whose rule the Mac edited stays where it was, as the user's own: run, with its severity, and stamped as
    /// not Mac Monitor's, so not edited either.
    func testTheMacsSetKeepsAnEditedOsascriptAsItsOwn() throws {
        let edited = try editedOsascript()
        let set = try loadedSet(try savedWithOsascript(edited))
        XCTAssertEqual(set.send(IndicatorRequest(.list)).indicators,
                       try defaultsWithOsascript().map { $0.id == Self.osascriptID ? edited : $0 })
        let hit = try XCTUnwrap(set.current.ruleHits.first { $0.id == Self.osascriptID })
        XCTAssertEqual([hit.isDefault, hit.edited], [false, false])
        XCTAssertEqual(hit.severity, .low)
    }

    /// Mac Monitor 3.0 saved a shipped indicator by identity unless its rule was edited. Its unedited osascript, on,
    /// off or shown elsewhere, is neither offered nor kept as a view switch. An edited one, saved before severities,
    /// is offered as the user's own, with an unknown one's medium, and imported as their own.
    func testAThreeZeroOsascriptIsOfferedOnlyWhenEdited() throws {
        var unedited = try droppedOsascript()
        unedited.isEnabled = false
        unedited.tableMarks = [.dot, .symbol]
        let legacy = try JSONSerialization.data(withJSONObject: savedWithOsascript(unedited))
        XCTAssertNil(IndicatorImportOffer(legacy: legacy, mac: Indicator.defaults))
        XCTAssertEqual(IndicatorOverlay.legacy(legacy, shipped: Indicator.defaults), IndicatorOverlay())

        let edited = try editedOsascript()
        var saved = try savedWithOsascript(edited)
        saved["entries"] = try XCTUnwrap(saved["entries"] as? [[String: Any]]).map { entry in
            guard (entry["id"] as? String) == Self.osascriptID.uuidString else { return entry }
            return entry.filter { !["tactic", "technique", "severity"].contains($0.key) }
        }
        XCTAssertNil(try osascriptEntry(in: saved)["severity"], "As 3.0 saved it")
        let offer = try XCTUnwrap(IndicatorImportOffer(legacy: JSONSerialization.data(withJSONObject: saved),
                                                       mac: Indicator.defaults))
        XCTAssertEqual(offer.edited, [])
        XCTAssertEqual(offer.added.map(\.id), [Self.osascriptID])
        XCTAssertEqual(offer.added.first?.predicate, edited.predicate)
        XCTAssertEqual(offer.added.first?.severity, .medium)

        let set = try makeSavedIndicatorSet()
        set.load()
        XCTAssertEqual(set.send(offer.request(replacingEdited: false)).status, .ok)
        let hit = try XCTUnwrap(set.current.ruleHits.first { $0.id == Self.osascriptID })
        XCTAssertEqual([hit.isDefault, hit.edited], [false, false])
    }

    /// On a Mac with several users, one user's edited 3.0 osascript the Mac already holds differently, as another
    /// user imported theirs, is offered as an edited one: it replaces the Mac's only when they opt in, keeping
    /// whether the Mac's is on and where it shows. The same edit as the Mac's isn't offered.
    func testAnotherUsersEditedOsascriptIsOfferedAsEdited() throws {
        var macs = try editedOsascript()
        macs.isEnabled = false
        macs.tableMarks = []
        let mac = Indicator.defaults + [macs]
        var mine = try droppedOsascript()
        mine.predicate += #" AND process.executable.name != "Terminal""#
        let legacy = try JSONSerialization.data(withJSONObject: savedWithOsascript(mine))
        let offer = try XCTUnwrap(IndicatorImportOffer(legacy: legacy, mac: mac))
        XCTAssertEqual(offer.added, [])
        XCTAssertEqual(offer.edited.map(\.id), [Self.osascriptID])
        XCTAssertEqual(offer.edited.first?.predicate, mine.predicate)
        XCTAssertEqual(offer.edited.first?.isEnabled, false, "The Mac's")
        XCTAssertEqual(offer.edited.first?.views, macs.views, "The Mac's")
        XCTAssertEqual(offer.request(replacingEdited: false).indicators, [])
        XCTAssertNil(IndicatorImportOffer(legacy: try JSONSerialization.data(withJSONObject: savedWithOsascript(
            try editedOsascript())), mac: mac), "Already the Mac's")
    }

    /// A user's view switches and Don't Notify for osascript outlast it harmlessly: the switches are still read back,
    /// and the silence isn't counted, until an edited osascript the Mac kept, which they still apply to.
    func testLeftoverViewsAndSilenceChangeNothing() throws {
        var views = try droppedOsascript().views
        views.tableMarks = [.dot, .symbol]
        let defaults = makeDefaults()
        IndicatorOverlay([Self.osascriptID: views]).save(to: defaults)
        let overlay = IndicatorOverlay(defaults: defaults)
        XCTAssertEqual(overlay.views, [Self.osascriptID: views], "Read back, not dropped")
        let alerts = IndicatorAlertSettings(high: true, medium: true, silenced: [Self.osascriptID])
        XCTAssertEqual(alerts.silencedCount(among: Indicator.defaults), 0)
        XCTAssertEqual(IndicatorAlertSettings(silenced: [Self.osascriptID, Indicator.defaults[0].id])
            .silencedCount(among: Indicator.defaults), 1)

        let kept = Indicator.defaults + [try editedOsascript()]
        XCTAssertEqual(alerts.silencedCount(among: kept), 1)
        XCTAssertEqual(overlay.applied(to: kept).last?.views, views)
    }

    /// A trace an earlier Security Extension stamped with osascript keeps that verdict: the dots show it from the
    /// verdict, with its name, tactic and severity, and the record lists it as Mac Monitor's, as it was.
    func testATraceStampedWithOsascriptKeepsTheVerdict() throws {
        let osascript = try droppedOsascript()
        let hit = IndicatorHit(osascript, against: Indicator.byID(try defaultsWithOsascript()),
                               evaluatedBy: .securityExtension)
        var message = try XCTUnwrap(try SyntheticCorpus.records().first?.message)
        message.indicators = IndicatorVerdicts([hit])
        try withEventStore([message]) { _, stored in
            let shown = try XCTUnwrap(EventIndicatorMatcher(Indicator.defaults).matches(stored[0]).first)
            XCTAssertEqual([shown.id.uuidString, shown.name], [Self.osascriptID.uuidString, "osascript"])
            XCTAssertEqual(shown.tactic, .execution)
            XCTAssertEqual(shown.severity, .low)
            let json = RecordIndicators.encoding(with: RecordIndicators(Indicator.defaults)) {
                ProcessHelpers.eventToJSON(value: stored[0])
            }
            let listed = try XCTUnwrap(try jsonObject(Data(json.utf8))["indicators"] as? [[String: Any]])
            XCTAssertEqual(listed.map { $0["id"] as? String }, [Self.osascriptID.uuidString])
            XCTAssertEqual(listed.first?["default"] as? Bool, true)
        }
    }

    // MARK: Helpers

    /// The directory of the set ``loadedSet(_:)`` made.
    private var directory: URL?

    /// A set the Security Extension loads from a saved file.
    ///
    /// - Parameter saved: The file's `saved` object.
    /// - Returns: The set, loaded.
    /// - Throws: If the directory or the file can't be made.
    private func loadedSet(_ saved: [String: Any]) throws -> SavedIndicatorSet {
        let directory = try makeIndicatorDirectory()
        self.directory = directory
        let file = try JSONSerialization.data(withJSONObject: ["version": IndicatorFile.currentVersion, "saved": saved])
        try writeIndicatorFile(file, in: directory)
        let set = try makeSavedIndicatorSet(in: directory)
        set.load()
        return set
    }
}
