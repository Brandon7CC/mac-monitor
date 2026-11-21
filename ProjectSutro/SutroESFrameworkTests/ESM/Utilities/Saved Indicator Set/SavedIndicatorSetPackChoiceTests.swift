//
//  SavedIndicatorSetPackChoiceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/16/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - What someone chose, across packs
/// Pins that a switch, severity or tactic someone chose for one of Mac Monitor's own indicators stays theirs through
/// every pack: when a pack comes to agree with it and a later one doesn't, when the pack that has the indicator is
/// away for a while, and until Restore Defaults forgets it. The build links in ``XCTestCase/linkedFixtures()``.
final class SavedIndicatorSetPackChoiceTests: XCTestCase {
    private var directory: URL!
    private var linked: [Indicator] = []

    /// A fresh directory, and the linked indicators.
    ///
    /// - Throws: If the directory can't be created or a fixture is missing.
    override func setUpWithError() throws {
        try super.setUpWithError()
        directory = try makeIndicatorDirectory()
        linked = try linkedFixtures()
    }

    /// A loaded set in the test's directory that trusts the fixtures' signer.
    ///
    /// - Returns: The set.
    /// - Throws: If it can't be made.
    private func loaded() throws -> SavedIndicatorSet {
        let set = try makeSavedIndicatorSet(in: directory, defaults: linked, verifier: try packVerifier())
        set.load()
        return set
    }

    /// The build's indicators as a later pack ships them: the first on or off, and the second at a severity.
    ///
    /// - Parameters:
    ///   - enabled: Is the first on?
    ///   - severity: The second's severity.
    ///   - revision: The first's revision, which each pack bumps.
    /// - Returns: The pack's indicators.
    private func shipped(enabled: Bool, severity: IndicatorSeverity, revision: Int) -> [Indicator] {
        var indicators = linked
        indicators[0].isEnabled = enabled
        indicators[0].revision = revision
        indicators[1].severity = severity
        return indicators
    }

    /// Someone turns an indicator off and raises another's severity. A pack that ships the first off and the second
    /// at that severity agrees with them. A later pack that ships the first on and the second low again doesn't
    /// change what they chose.
    func testAChoiceStaysWhenAPackComesToAgreeWithIt() throws {
        let set = try loaded()
        var raised = linked[1]
        raised.severity = .high
        XCTAssertEqual(set.send(IndicatorRequest(.setEnabled, ids: [linked[0].id], enabled: false)).status, .ok)
        XCTAssertEqual(set.send(IndicatorRequest(.add, indicators: [raised])).status, .ok)

        let agreeing = shipped(enabled: false, severity: .high, revision: 2)
        let second = set.take(verified(try packPayload(sequence: 2, agreeing)))
        XCTAssertEqual(second.status, .ok, second.failure ?? "")
        XCTAssertEqual(second.indicators, agreeing)

        let differing = shipped(enabled: true, severity: .low, revision: 3)
        let third = set.take(verified(try packPayload(sequence: 3, differing)))
        XCTAssertEqual(third.status, .ok, third.failure ?? "")
        XCTAssertEqual(third.indicators[0].isEnabled, false, "They turned it off")
        XCTAssertEqual(third.indicators[0].revision, 3, "The rest is the pack's")
        XCTAssertEqual(third.indicators[1].severity, .high, "They raised it")
        XCTAssertEqual(try savedIndicators(in: directory, defaults: differing), third.indicators, "And as saved")
    }

    /// A choice made back to what Mac Monitor ships is still a choice, once it was one.
    func testAChoiceTurnedBackStaysWhereItWasPut() throws {
        let set = try loaded()
        let id = linked[0].id
        XCTAssertEqual(set.send(IndicatorRequest(.setEnabled, ids: [id], enabled: false)).status, .ok)
        let off = shipped(enabled: false, severity: .low, revision: 2)
        XCTAssertEqual(set.take(verified(try packPayload(sequence: 2, off))).status, .ok)
        XCTAssertEqual(set.send(IndicatorRequest(.setEnabled, ids: [id], enabled: true)).status, .ok)
        let stillOff = shipped(enabled: false, severity: .low, revision: 3)
        XCTAssertEqual(set.take(verified(try packPayload(sequence: 3, stillOff))).indicators[0].isEnabled, true)
    }

    /// Restore Defaults forgets what someone chose, even when the indicators already are Mac Monitor's own, so each
    /// follows the packs again.
    func testRestoreDefaultsForgetsChoices() throws {
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.setEnabled, ids: [linked[0].id], enabled: false)).status, .ok)
        let agreeing = shipped(enabled: false, severity: .low, revision: 2)
        XCTAssertEqual(set.take(verified(try packPayload(sequence: 2, agreeing))).indicators, agreeing)

        let restored = set.send(IndicatorRequest(.reset))
        XCTAssertEqual(restored.status, .ok)
        XCTAssertEqual(restored.indicators, agreeing)
        XCTAssertTrue(restored.changed, "The choice was forgotten")
        XCTAssertFalse(set.send(IndicatorRequest(.reset)).changed, "Nothing more to forget")

        let differing = shipped(enabled: true, severity: .low, revision: 3)
        XCTAssertEqual(set.take(verified(try packPayload(sequence: 3, differing))).indicators, differing)
    }

    /// An indicator only a pack has keeps its switch while the pack is away: set aside at a restart, then installed
    /// again, the indicator is as someone left it, not as a new arrival.
    func testAPackOnlyIndicatorKeepsItsSwitchWhileThePackIsAway() throws {
        let (file, pack) = try releaseFixture(2)
        let added = pack.indicators[2]
        XCTAssertFalse(added.isEnabled, "The pack ships it off")
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.installPack, pack: file)).status, .ok)
        XCTAssertEqual(set.send(IndicatorRequest(.setEnabled, ids: [added.id], enabled: true)).status, .ok)

        try writeIndicatorFile(Data("nope".utf8), named: IndicatorPackFile.installedLayout.fileName, in: directory)
        let away = try loaded()
        let without = away.send(IndicatorRequest(.list))
        XCTAssertFalse(without.indicators.contains { $0.id == added.id })
        XCTAssertEqual(without.pack?.source, .linked)
        XCTAssertEqual(away.send(IndicatorRequest(.setEnabled, ids: [linked[0].id], enabled: false)).status, .ok,
                       "A change while it's away keeps the reference")

        let back = away.send(IndicatorRequest(.installPack, pack: file))
        XCTAssertEqual(back.status, .ok, back.failure ?? "")
        XCTAssertEqual(back.indicators.first { $0.id == added.id }?.isEnabled, true, "As they left it")
        XCTAssertEqual(back.indicators.filter { $0.id == added.id }.count, 1)
    }

    /// While a pack is away, an indicator of someone's own with the identity of one the pack has takes its place.
    /// When the pack comes back the identity is listed once.
    func testAnIdentityIsListedOnceWhenItsPackComesBack() throws {
        let (file, pack) = try releaseFixture(2)
        let added = pack.indicators[2]
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.installPack, pack: file)).status, .ok)
        XCTAssertEqual(set.send(IndicatorRequest(.setEnabled, ids: [added.id], enabled: true)).status, .ok)
        try writeIndicatorFile(Data("nope".utf8), named: IndicatorPackFile.installedLayout.fileName, in: directory)

        let away = try loaded()
        var mine = added
        mine.rule = .event(added.predicate! + " AND process.pid > 1")
        XCTAssertEqual(away.send(IndicatorRequest(.add, indicators: [mine])).status, .ok)
        let back = away.send(IndicatorRequest(.installPack, pack: file))
        XCTAssertEqual(back.status, .ok, back.failure ?? "")
        XCTAssertEqual(back.indicators.filter { $0.id == added.id }, [mine])
    }

    /// A reference to an indicator a pack only dropped is kept in the saved file, in case a later pack brings it
    /// back. One to an identity the pack retires, which is never used again, is dropped from it.
    func testAReferenceToARetiredIdentityIsDropped() throws {
        var retiring = linked[2]
        retiring.id = Self.retiredFixtureID
        retiring.name = "Fixture retired"
        linked.append(retiring)
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.setEnabled, ids: [linked[2].id, retiring.id],
                                                 enabled: false)).status, .ok)
        let before = String(decoding: try XCTUnwrap(indicatorFile(in: directory)), as: UTF8.self)
        XCTAssertTrue(before.contains(retiring.id.uuidString) && before.contains(linked[2].id.uuidString))

        let reply = set.send(IndicatorRequest(.installPack, pack: try releaseFixture(2).file))
        XCTAssertEqual(reply.status, .ok, reply.failure ?? "")
        XCTAssertEqual(reply.indicators, try releaseFixture(2).pack.indicators, "Neither is listed")
        let after = String(decoding: try XCTUnwrap(indicatorFile(in: directory)), as: UTF8.self)
        XCTAssertTrue(after.contains(linked[2].id.uuidString), "Only dropped: its reference is kept")
        XCTAssertFalse(after.contains(retiring.id.uuidString), "Retired: its reference is gone")
    }

    /// Restore Defaults also forgets the references kept for indicators a pack may bring back.
    func testRestoreDefaultsForgetsKeptReferences() throws {
        let (file, pack) = try releaseFixture(2)
        let added = pack.indicators[2]
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.installPack, pack: file)).status, .ok)
        XCTAssertEqual(set.send(IndicatorRequest(.setEnabled, ids: [added.id], enabled: true)).status, .ok)
        try writeIndicatorFile(Data("nope".utf8), named: IndicatorPackFile.installedLayout.fileName, in: directory)

        let away = try loaded()
        XCTAssertTrue(away.send(IndicatorRequest(.reset)).changed)
        let back = away.send(IndicatorRequest(.installPack, pack: file))
        XCTAssertEqual(back.indicators.first { $0.id == added.id }?.isEnabled, false, "As the pack ships it")
    }
}
