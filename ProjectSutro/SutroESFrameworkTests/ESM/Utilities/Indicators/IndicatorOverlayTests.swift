//
//  IndicatorOverlayTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - One user's view switches
/// Pins what's one user's of the Mac's indicators: only where each shows, in Correlation, Groups and the tables. They
/// apply over the Mac's set, are kept in the user's defaults, and start, once, from what the user chose in Mac Monitor
/// 3.0, whose `findings` default is never written.
final class IndicatorOverlayTests: XCTestCase {
    /// An indicator's views are its table marks, and nothing else.
    func testViewsAreOnlyWhereItShows() throws {
        let shipped = try XCTUnwrap(Indicator.defaults.first)
        var other = ownIndicator("Other", #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#, severity: .high)
        other.tableMarks = shipped.tableMarks.isEmpty ? [.dot, .symbol] : []
        other.isEnabled = !shipped.isEnabled
        var viewed = shipped
        viewed.copyViews(from: other)
        XCTAssertEqual(viewed.views, other.views)
        XCTAssertEqual(viewed.tableMarks, other.tableMarks)
        viewed.views = shipped.views
        XCTAssertEqual(viewed, shipped, "Only the views changed")
        var switched = shipped
        switched.copyViews(from: other)
        XCTAssertEqual(switched.isEnabled, shipped.isEnabled)
        XCTAssertEqual(switched.predicate, shipped.predicate)
        XCTAssertEqual(switched.severity, shipped.severity)
    }

    /// A user's views apply over the Mac's set, whatever else the Mac's indicator says, and are kept: a new overlay
    /// on the same defaults reads them back. Keeping the same views again changes nothing, and Restore Defaults
    /// forgets them.
    func testViewsApplyAndAreKept() throws {
        let defaults = makeDefaults()
        var overlay = IndicatorOverlay(defaults: defaults)
        XCTAssertTrue(overlay.views.isEmpty)
        XCTAssertEqual(overlay.applied(to: Indicator.defaults), Indicator.defaults)

        var mine = Indicator.defaults[2]
        mine.tableMarks = []
        mine.isEnabled = !mine.isEnabled
        XCTAssertTrue(overlay.keep(mine, mac: Indicator.defaults[2]))
        XCTAssertFalse(overlay.keep(mine, mac: Indicator.defaults[2]), "Nothing new")
        overlay.save(to: defaults)

        var mac = Indicator.defaults
        mac[2].severity = .high
        let applied = IndicatorOverlay(defaults: defaults).applied(to: mac)
        XCTAssertEqual(applied[2].views, mine.views)
        XCTAssertEqual(applied[2].isEnabled, mac[2].isEnabled, "Whether it's on is the Mac's")
        XCTAssertEqual(applied[2].severity, .high)
        XCTAssertEqual(Array(applied[3...]), Array(mac[3...]))

        overlay.removeAll()
        overlay.save(to: defaults)
        XCTAssertTrue(IndicatorOverlay(defaults: defaults).views.isEmpty)
    }

    /// A switch turned off and back on leaves no view switches behind: views equal to the Mac's are forgotten, so
    /// Restore Defaults has nothing to restore and the Mac's later changes show. An indicator the Mac's set doesn't
    /// have yet keeps the user's views.
    func testViewsBackToTheMacsAreForgotten() throws {
        let mac = try XCTUnwrap(Indicator.defaults.first)
        var overlay = IndicatorOverlay()
        var off = mac
        off.tableMarks = mac.tableMarks.isEmpty ? .dot : []
        XCTAssertTrue(overlay.keep(off, mac: mac))
        XCTAssertEqual(overlay.views[mac.id], off.views)
        XCTAssertTrue(overlay.keep(mac, mac: mac), "Back to the Mac's")
        XCTAssertTrue(overlay.views.isEmpty)
        XCTAssertFalse(overlay.keep(mac, mac: mac), "Nothing to forget")
        XCTAssertTrue(overlay.views.isEmpty)

        let new = ownIndicator("New", #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#, severity: .low)
        XCTAssertTrue(overlay.keep(new, mac: nil))
        XCTAssertEqual(overlay.views[new.id], new.views)
    }

    /// The first read keeps the views a Mac Monitor 3.0 user chose: of their own indicators, and of shipped ones
    /// whose views they changed, not whether any is on. Their `findings` default is untouched, and a later change
    /// to it isn't read again.
    func testItStartsFromTheUsers30Views() throws {
        let defaults = makeDefaults()
        var legacy = Indicator.defaults
        legacy[0].tableMarks = legacy[0].tableMarks == [.dot, .symbol] ? .dot : [.dot, .symbol]
        legacy[1].isEnabled.toggle()
        var own = ownIndicator("Mine", #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#)
        own.tableMarks = []
        legacy.append(own)
        let data = try XCTUnwrap(SavedIndicators(legacy).encoded())
        defaults.set(data, forKey: IndicatorImportOffer.legacyKey)

        let overlay = IndicatorOverlay(defaults: defaults)
        XCTAssertEqual(Set(overlay.views.keys), [legacy[0].id, own.id])
        XCTAssertEqual(overlay.views[legacy[0].id], legacy[0].views)
        XCTAssertEqual(overlay.views[own.id]?.tableMarks, [])
        XCTAssertEqual(defaults.data(forKey: IndicatorImportOffer.legacyKey), data, "Untouched")
        XCTAssertNotNil(defaults.data(forKey: IndicatorOverlay.key))

        defaults.set(try XCTUnwrap(SavedIndicators(Indicator.defaults).encoded()),
                     forKey: IndicatorImportOffer.legacyKey)
        XCTAssertEqual(IndicatorOverlay(defaults: defaults), overlay, "Read once")
    }

    /// Views that can't be read are none, and so are those of an identity that isn't one.
    func testUnreadableViewsAreNone() {
        let defaults = makeDefaults()
        defaults.set(Data("[]".utf8), forKey: IndicatorOverlay.key)
        XCTAssertTrue(IndicatorOverlay(defaults: defaults).views.isEmpty)
        defaults.set(Data(#"{"not-an-id": {"showsInCorrelation": true, "showsInGroups": true, "tableMark": "dot"}}"#
            .utf8), forKey: IndicatorOverlay.key)
        XCTAssertTrue(IndicatorOverlay(defaults: defaults).views.isEmpty)
    }

    /// A user's views saved by 3.1's betas, one mark and the Correlation and Groups switches, read as that mark's
    /// set, and are written as the set alone.
    func testBetaViewsReadAsTheirMarks() throws {
        let id = try XCTUnwrap(Indicator.defaults.first).id
        let defaults = makeDefaults()
        let saved = #"{"\#(id.uuidString)": {"showsInCorrelation": false, "showsInGroups": true, "#
            + #""tableMark": "label"}}"#
        defaults.set(Data(saved.utf8), forKey: IndicatorOverlay.key)
        let overlay = IndicatorOverlay(defaults: defaults)
        XCTAssertEqual(overlay.views[id]?.tableMarks, [.dot, .symbol, .label])
        let written = try JSONEncoder().encode(try XCTUnwrap(overlay.views[id]))
        XCTAssertEqual(String(decoding: written, as: UTF8.self), #"{"tableMarks":["dot","symbol","label"]}"#)
    }
}
