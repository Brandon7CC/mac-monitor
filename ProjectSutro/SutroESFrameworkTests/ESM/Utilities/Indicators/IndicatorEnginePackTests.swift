//
//  IndicatorEnginePackTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Mac Monitor's side of indicator packs
/// Pins what Mac Monitor learns and asks about indicator packs: a look says what a newer pack would change without
/// changing the set shown, an install brings only the pack that was offered, the mode is the Mac's, and Settings'
/// words for each. GitHub is a ``FakePackFetcher``, and the build links in ``XCTestCase/linkedFixtures()``.
final class IndicatorEnginePackTests: XCTestCase {
    private var github = FakePackFetcher()
    private var clock = TestClock()
    private var linked: [Indicator] = []

    /// A fresh GitHub and clock.
    ///
    /// - Throws: If a fixture is missing.
    override func setUpWithError() throws {
        try super.setUpWithError()
        github = FakePackFetcher()
        clock = TestClock()
        linked = try linkedFixtures()
    }

    /// An engine connected to a loaded set that asks the test's GitHub, as a caller with `access`, once it has
    /// listed the set.
    ///
    /// - Parameter access: What Mac Monitor may do.
    /// - Returns: The engine and the set.
    /// - Throws: If the set can't be made.
    private func connected(access: MuteAccess = .write) throws -> (IndicatorEngine, SavedIndicatorSet) {
        let clock = clock
        let set = try makeSavedIndicatorSet(defaults: linked, verifier: try packVerifier(), fetcher: github,
                                            clock: { clock.now })
        set.load()
        let engine = IndicatorEngine(defaults: makeDefaults(), transport: transport(to: set, access: access))
        send(IndicatorRequest(.list), through: engine)
        return (engine, set)
    }

    /// Look for a pack through an engine, and wait for the look and the list it asks for afterwards.
    ///
    /// - Parameter engine: The engine.
    /// - Returns: How the look went.
    private func look(_ engine: IndicatorEngine) -> IndicatorPackLook {
        let looked = expectation(description: "The look")
        var outcome = IndicatorPackLook.failed("No answer.")
        engine.lookForPack {
            outcome = $0
            looked.fulfill()
        }
        wait(for: [looked], timeout: 30)
        send(IndicatorRequest(.list), through: engine)
        return outcome
    }

    /// A look finds a newer pack and says what installing it would do. The set shown is still the Mac's, the offer
    /// is kept, and the Security Extension's status says the pack is out.
    func testALookOffersANewerPackWithoutChangingTheSet() throws {
        let pack = try releaseFixture(2).pack
        github.offer([("pack-2", try releaseFixture(2).file)], notes: "## Pack 2")
        let (engine, _) = try connected()
        XCTAssertNil(engine.packOffer)
        let offer = IndicatorPackOffer(sequence: 2, added: [pack.indicators[2].name], removed: ["Fixture dropped"],
                                       changed: [pack.indicators[0].name], total: pack.indicators.count,
                                       published: pack.pack.published, notes: "## Pack 2")
        XCTAssertEqual(offer.total, 3)
        XCTAssertEqual(look(engine), .newer(offer))
        XCTAssertFalse(engine.isLookingForPack)
        XCTAssertEqual(engine.packOffer, offer)
        XCTAssertEqual(engine.indicators, linked, "The preview isn't shown as the set")
        XCTAssertEqual(engine.baseline, linked)
        XCTAssertEqual(engine.pack?.sequence, 0)
        XCTAssertEqual(engine.pack?.available, 2)
        XCTAssertNil(engine.failure)
    }

    /// With nothing newer, a look says so and offers nothing. GitHub not answering is a failure with the reason,
    /// which keeps an offer made before.
    func testALookThatFindsNothing() throws {
        github.offer([])
        let (engine, _) = try connected()
        XCTAssertEqual(look(engine), .upToDate)
        XCTAssertNil(engine.packOffer)

        github.offer([("pack-2", try releaseFixture(2).file)])
        clock.advance(by: IndicatorPackUpdates.answerLifetime)
        guard case .newer(let offer) = look(engine) else { return XCTFail("No offer") }
        github.answer(IndicatorPackRelease.releasesURL, with: .failure(.unreachable("Offline.")))
        clock.advance(by: IndicatorPackUpdates.answerLifetime)
        XCTAssertEqual(look(engine), .failed("GitHub couldn't be reached. Offline."))
        XCTAssertEqual(engine.packOffer, offer)
        XCTAssertEqual(engine.pack?.problem, "GitHub couldn't be reached. Offline.")
        XCTAssertNil(engine.failure, "A look isn't a change that failed")
    }

    /// Installing the offered pack shows the set it makes, and the offer is gone. A failed install says why where
    /// it was asked, not as a failed change.
    func testInstallingTheOfferedPack() throws {
        github.offer([("pack-2", try releaseFixture(2).file)])
        let (engine, _) = try connected()
        guard case .newer(let offer) = look(engine) else { return XCTFail("No offer") }
        let installed = expectation(description: "The install")
        engine.installPack(offer) { problem in
            XCTAssertNil(problem)
            installed.fulfill()
        }
        wait(for: [installed], timeout: 30)
        XCTAssertEqual(engine.indicators, try releaseFixture(2).pack.indicators)
        XCTAssertEqual(engine.pack?.sequence, 2)
        XCTAssertNil(engine.packOffer)

        let again = expectation(description: "A second install")
        engine.installPack(offer) { problem in
            XCTAssertEqual(problem, "There's no newer indicator pack to install.")
            again.fulfill()
        }
        wait(for: [again], timeout: 30)
        XCTAssertNil(engine.failure)
    }

    /// An install brings only the pack that was offered: when a later one is out by then, it's refused, and nothing
    /// is installed.
    func testAnInstallBringsOnlyThePackThatWasOffered() throws {
        github.offer([("pack-2", try releaseFixture(2).file)])
        let (engine, _) = try connected()
        guard case .newer(let offer) = look(engine) else { return XCTFail("No offer") }
        github.offer([("pack-3", try releaseFixture(3).file)])
        clock.advance(by: IndicatorPackUpdates.answerLifetime)
        let refused = expectation(description: "The install")
        engine.installPack(offer) { problem in
            XCTAssertEqual(problem, "Pack 3 is out now, not pack 2, which was checked. Check again before installing.")
            refused.fulfill()
        }
        wait(for: [refused], timeout: 30)
        XCTAssertEqual(engine.indicators, linked)
    }

    /// The mode is the Mac's: setting it shows in the status, and a Mac Monitor that may only read can't.
    func testTheMode() throws {
        let (engine, _) = try connected()
        XCTAssertEqual(engine.pack?.mode, .notify)
        engine.setPackMode(.automatic)
        send(IndicatorRequest(.list), through: engine)
        XCTAssertEqual(engine.pack?.mode, .automatic)

        let (reader, _) = try connected(access: .read)
        reader.setPackMode(.off)
        send(IndicatorRequest(.list), through: reader)
        XCTAssertEqual(reader.pack?.mode, .notify)
        XCTAssertNotNil(reader.failure)
    }

    /// What an offer would do reads as the rest of a sentence, leaving out what it doesn't do.
    func testWhatAnOfferWouldDo() {
        let effects: [(IndicatorPackOffer, String)] = [
            (IndicatorPackOffer(sequence: 2, added: names(3), removed: names(1), changed: names(5)),
             "adds 3 indicators, removes 1 and changes 5"),
            (IndicatorPackOffer(sequence: 2, added: names(1), changed: names(2)), "adds 1 indicator and changes 2"),
            (IndicatorPackOffer(sequence: 2, changed: names(4)), "changes 4"),
            (IndicatorPackOffer(sequence: 2, removed: names(2)), "removes 2"),
            (IndicatorPackOffer(sequence: 2), "changes none of this Mac's indicators"),
        ]
        for (offer, effect) in effects {
            XCTAssertEqual(offer.effect, effect)
        }
    }

    /// - Parameter count: How many.
    /// - Returns: That many indicator names.
    private func names(_ count: Int) -> [String] {
        (0..<count).map { "Indicator \($0)" }
    }

    /// The offer's sheet says which pack is out over which, this Mac's version and the pack's, the day its commit
    /// was made, and where its release is.
    func testWhatTheOfferSays() throws {
        let offer = IndicatorPackOffer(sequence: 2, published: "2026-11-15T23:35:16Z")
        XCTAssertEqual(IndicatorPackText.availability(of: offer, over: IndicatorPackStatus(sequence: 1,
                                                                                           source: .installed)),
                       "Indicator pack 2 is available. You have pack 1.")
        XCTAssertEqual(IndicatorPackText.versions(of: offer, over: IndicatorPackStatus(sequence: 1,
                                                                                       source: .installed)),
                       "v1 → v2")
        for own in [nil, IndicatorPackStatus(sequence: 0, source: .linked)] {
            XCTAssertEqual(IndicatorPackText.availability(of: offer, over: own),
                           "Indicator pack 2 is available. You have the indicators this Mac Monitor came with.")
            XCTAssertEqual(IndicatorPackText.versions(of: offer, over: own), "v0 → v2")
        }
        let utc = try XCTUnwrap(TimeZone(identifier: "UTC")), tokyo = try XCTUnwrap(TimeZone(identifier: "Asia/Tokyo"))
        XCTAssertEqual(IndicatorPackText.day(offer.published, in: utc), "November 15, 2026")
        XCTAssertEqual(IndicatorPackText.day(offer.published, in: tokyo), "November 16, 2026")
        XCTAssertNil(IndicatorPackText.day(nil))
        XCTAssertNil(IndicatorPackText.day("yesterday"))
        XCTAssertEqual(offer.page.absoluteString,
                       "https://github.com/Brandon7CC/mac-monitor-indicators/releases/tag/pack-2")
    }

    /// Settings' pack row names the pack and says what the last look found, and when. The mode's row says what each
    /// mode does.
    func testWhatSettingsSays() {
        let now = Self.packClock, english = Locale(identifier: "en_US")
        let detail = { (pack: IndicatorPackStatus?) in
            IndicatorPackText.detail(pack, now: now, locale: english)
        }
        let own = IndicatorPackStatus(sequence: 0, source: .linked)
        XCTAssertEqual(IndicatorPackText.title(nil), "Indicator pack")
        XCTAssertEqual(IndicatorPackText.title(own), "Indicator pack")
        XCTAssertEqual(IndicatorPackText.title(IndicatorPackStatus(sequence: 3, source: .installed)),
                       "Indicator pack 3")
        XCTAssertEqual(detail(nil), "The Security Extension hasn't said which indicators it has.")
        XCTAssertEqual(detail(own), "Mac Monitor's own indicators are the ones this build came with.")
        XCTAssertEqual(detail(IndicatorPackStatus(sequence: 3, source: .installed)),
                       "It hasn't looked for a newer pack yet.")
        let checked = { (ago: TimeInterval, sequence: Int) in
            IndicatorPackStatus(sequence: sequence, source: sequence == 0 ? .linked : .installed,
                                checked: ISO8601DateFormatter().string(from: now - ago))
        }
        XCTAssertEqual(detail(checked(7_200, 3)), "Up to date. Checked 2 hours ago.")
        XCTAssertEqual(detail(checked(10, 3)), "Up to date. Checked just now.")
        XCTAssertEqual(detail(checked(86_400, 0)),
                       "Mac Monitor's own indicators are the ones this build came with. Checked 1 day ago.")
        var out = checked(7_200, 3)
        out.available = 4
        XCTAssertEqual(detail(out), "Pack 4 is out.")
        out.problem = "GitHub couldn't be reached. Offline."
        XCTAssertEqual(detail(out), "GitHub couldn't be reached. Offline.")
        XCTAssertEqual(IndicatorPackText.detail(out, isLooking: true), "Looking for a newer pack.")

        XCTAssertEqual(IndicatorPackMode.allCases.map(IndicatorPackText.name), ["Off", "Notify me",
                                                                               "Install automatically"])
        for mode in IndicatorPackMode.allCases + [nil] {
            XCTAssertTrue(IndicatorPackText.detail(of: mode).hasSuffix("."))
        }
    }
}
