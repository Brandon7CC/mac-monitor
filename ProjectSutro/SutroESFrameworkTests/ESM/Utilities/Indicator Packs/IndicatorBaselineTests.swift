//
//  IndicatorBaselineTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/16/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The indicator baseline
/// Pins which pack may take a baseline's place, what a baseline says about itself, and what each refusal says.
final class IndicatorBaselineTests: XCTestCase {
    /// Indicators linked in without a pack are release 0, with nothing from a pack. The build's own are a pack's
    /// (``LinkedIndicatorPackTests``).
    func testIndicatorsWithoutAPackAreNoRelease() throws {
        let linked = IndicatorBaseline(linked: try linkedFixtures())
        XCTAssertEqual(linked.source, .linked)
        XCTAssertEqual(linked.sequence, 0)
        XCTAssertEqual(linked.indicators, try linkedFixtures())
        XCTAssertNil(linked.commit)
        XCTAssertEqual(linked.status(linked: 0), IndicatorPackStatus(sequence: 0, source: .linked))
    }

    /// A later release takes a baseline's place, with the pack's header and every entry.
    func testALaterReleaseTakesItsPlace() throws {
        let (file, pack) = try releaseFixture(3)
        let next = try IndicatorBaseline(linked: try linkedFixtures())
            .replacement(from: try IndicatorPackFile(file).payload)
        XCTAssertEqual(next, IndicatorBaseline(installed: pack))
        XCTAssertEqual(next.source, .installed)
        XCTAssertEqual(next.sequence, 3)
        XCTAssertEqual(next.indicators, pack.indicators)
        XCTAssertEqual(next.newer.count, 1)
        XCTAssertEqual(next.status(linked: 1), IndicatorPackStatus(sequence: 3, source: .installed,
                                                                   published: "2026-11-16T00:00:00Z",
                                                                   commit: String(repeating: "3", count: 40),
                                                                   linked: 1, needsNewer: 1))
    }

    /// An indicator this build reads but can't run counts as needing a newer Mac Monitor, as an entry it can't read
    /// does.
    func testIndicatorsThatNeedANewerMacMonitorAreCounted() throws {
        var later = ownIndicator("Later", #"event.exec != nil"#)
        later.minEngine = ReleaseVersion(9, 0, 0)
        let payload = try packPayload(sequence: 1, [ownIndicator("Now", #"event.exec != nil"#), later])
        let baseline = try IndicatorBaseline(linked: try linkedFixtures()).replacement(from: payload)
        XCTAssertEqual(baseline.status(linked: 0).needsNewer, 1)
    }

    /// A release no later than the baseline is refused, and so is a payload that isn't a pack.
    func testWhatIsRefused() throws {
        let payload = try IndicatorPackFile(try releaseFixture(2).file).payload
        let linked = IndicatorBaseline(linked: try linkedFixtures())
        let installed = try linked.replacement(from: payload)
        let refusal = { (baseline: IndicatorBaseline, payload: Data) in
            thrown(IndicatorPackRefusal.self) { try baseline.replacement(from: payload) }
        }
        XCTAssertEqual(refusal(installed, payload), .notNewer(offered: 2, current: 2, source: .installed))
        XCTAssertEqual(refusal(IndicatorBaseline(linked: [], sequence: 4), payload),
                       .notNewer(offered: 2, current: 4, source: .linked))
        XCTAssertEqual(refusal(linked, Data("{}".utf8)), .payload("It isn't Mac Monitor indicators."))
        XCTAssertEqual(refusal(linked, try IndicatorPackFile(try fixture("indicator-pack.json")).payload),
                       .payload("It has no indicators."))
    }

    /// Each refusal is a sentence the user reads.
    func testRefusalsAreSentences() {
        let sentences: [(IndicatorPackRefusal, String)] = [
            (.signature("The pack isn't signed."), "The pack wasn't installed. The pack isn't signed."),
            (.payload("It has no indicators."),
             "The pack is signed, but it isn't one this Mac Monitor installs. It has no indicators."),
            (.notNewer(offered: 4, current: 4, source: .installed), "Pack 4 is already installed."),
            (.notNewer(offered: 3, current: 4, source: .installed),
             "Pack 3 is older than pack 4, which is installed."),
            (.notNewer(offered: 3, current: 4, source: .linked),
             "Pack 3 isn't newer than the indicators this Mac Monitor came with (pack 4)."),
            (.cannotRun(name: "Mine", reason: "It uses MATCHES."),
             "The pack wasn't installed, because this Mac Monitor can't run its indicator “Mine”. It uses "
                + "MATCHES."),
            (.pastLimit("It has 2049 indicators."),
             "The pack wasn't installed, because this Mac's indicators would be past a limit with it. It has 2049 "
                + "indicators."),
            (.storage("The disk is full."), "The pack couldn't be kept, so nothing changed. The disk is full."),
        ]
        for (refusal, sentence) in sentences {
            XCTAssertEqual(refusal.description, sentence)
        }
    }
}
