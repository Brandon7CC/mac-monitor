//
//  IndicatorImportOfferTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Offering a user's 3.0 indicators
/// Pins the one offer of a user's Mac Monitor 3.0 indicators to the Mac's set: only their own the Mac doesn't have,
/// edited shipped ones only with their own opt-in, never a shipped one they turned off or deleted, made once, and
/// their `findings` default never written.
final class IndicatorImportOfferTests: XCTestCase {
    /// Every exec.
    private static let exec = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#

    /// - Parameter indicators: A user's 3.0 indicators.
    /// - Returns: Their `findings` default, as Mac Monitor 3.0 saved it.
    /// - Throws: A failure when they can't be encoded.
    private func legacy(_ indicators: [Indicator]) throws -> Data {
        try XCTUnwrap(SavedIndicators(indicators).encoded())
    }

    /// Only the user's own indicators are offered, and only those the Mac doesn't have, such as one another user
    /// already imported. An import is an add.
    func testOnlyAddedIndicatorsAreOffered() throws {
        let first = ownIndicator("First", Self.exec), second = ownIndicator("Second", Self.exec, severity: .high)
        let data = try legacy(Indicator.defaults + [first, second])
        let offer = try XCTUnwrap(IndicatorImportOffer(legacy: data, mac: Indicator.defaults + [second]))
        XCTAssertEqual(offer.added, [first])
        XCTAssertEqual(offer.edited, [])
        XCTAssertEqual(offer.request(replacingEdited: true), IndicatorRequest(.add, indicators: [first]))
        XCTAssertNil(IndicatorImportOffer(legacy: try legacy(Indicator.defaults), mac: Indicator.defaults))
        XCTAssertNil(IndicatorImportOffer(legacy: nil, mac: Indicator.defaults))
        XCTAssertNil(IndicatorImportOffer(legacy: Data("not findings".utf8), mac: Indicator.defaults))
    }

    /// A shipped indicator the user edited is offered on its own, and imported only when they opt in. It keeps the
    /// Mac's on or off and view switches, and isn't offered once the Mac has the same detection.
    func testEditedIndicatorsNeedTheirOwnOptIn() throws {
        let own = ownIndicator("Mine", Self.exec)
        var edited = Indicator.defaults
        edited[0].predicate += " AND process.pid > 1"
        edited[0].isEnabled = true
        edited[0].tableMarks = []
        var mac = Indicator.defaults
        mac[0].isEnabled = false
        let offer = try XCTUnwrap(IndicatorImportOffer(legacy: try legacy(edited + [own]), mac: mac))
        XCTAssertEqual(offer.added, [own])
        XCTAssertEqual(offer.edited.map(\.id), [edited[0].id])
        XCTAssertEqual(offer.edited.first?.predicate, edited[0].predicate)
        XCTAssertEqual(offer.edited.first?.isEnabled, false, "The Mac's")
        XCTAssertEqual(offer.edited.first?.views, mac[0].views, "The Mac's")
        XCTAssertEqual(offer.request(replacingEdited: false).indicators, [own])
        XCTAssertEqual(offer.request(replacingEdited: true).indicators.map(\.id), [own.id, edited[0].id])

        var imported = mac
        imported[0].predicate = edited[0].predicate
        XCTAssertNil(IndicatorImportOffer(legacy: try legacy(edited), mac: imported), "Already the Mac's")
    }

    /// A shipped indicator the user turned off, moved in the tables or deleted is never offered, and importing the
    /// rest through the Security Extension leaves it as the Mac has it.
    func testDisablesAndDeletionsAreNeverCarried() throws {
        var changed = Indicator.defaults
        changed[0].isEnabled = false
        changed[1].tableMarks = []
        changed.remove(at: 2)
        XCTAssertNil(IndicatorImportOffer(legacy: try legacy(changed), mac: Indicator.defaults))

        let own = ownIndicator("Mine", Self.exec)
        let offer = try XCTUnwrap(IndicatorImportOffer(legacy: try legacy(changed + [own]), mac: Indicator.defaults))
        let set = try makeSavedIndicatorSet()
        set.load()
        XCTAssertEqual(set.send(offer.request(replacingEdited: true)).status, .ok)
        let after = set.send(IndicatorRequest(.list)).indicators
        XCTAssertEqual(after, Indicator.defaults + [own])
    }

    /// The offer is made until it's taken or declined, and the user's `findings` default is only ever read.
    func testItIsOfferedOnceAndTheirDefaultIsUntouched() throws {
        let defaults = makeDefaults()
        XCTAssertNil(IndicatorImportOffer.pending(in: defaults, mac: Indicator.defaults))
        let data = try legacy(Indicator.defaults + [ownIndicator("Mine", Self.exec)])
        defaults.set(data, forKey: IndicatorImportOffer.legacyKey)
        XCTAssertEqual(IndicatorImportOffer.pending(in: defaults, mac: Indicator.defaults)?.added.map(\.name), ["Mine"])
        IndicatorImportOffer.markOffered(in: defaults)
        XCTAssertNil(IndicatorImportOffer.pending(in: defaults, mac: Indicator.defaults))
        XCTAssertEqual(defaults.data(forKey: IndicatorImportOffer.legacyKey), data)
    }
}
