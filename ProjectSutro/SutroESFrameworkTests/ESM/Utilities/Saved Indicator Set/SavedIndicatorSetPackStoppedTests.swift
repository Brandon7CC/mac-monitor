//
//  SavedIndicatorSetPackStoppedTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/16/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - A pack the Security Extension stopped over
/// Pins that a pack the Security Extension stopped while checking isn't tried for ever: a marker names the packs
/// being checked, one left behind at a restart counts against each, and a pack that has stopped it twice is passed
/// over, from GitHub or from a file, while a later one is still taken. GitHub is a ``FakePackFetcher``.
final class SavedIndicatorSetPackStoppedTests: XCTestCase {
    private var directory: URL!
    private var linked: [Indicator] = []
    private var github = FakePackFetcher()

    /// A fresh directory and GitHub.
    ///
    /// - Throws: If the directory can't be created or a fixture is missing.
    override func setUpWithError() throws {
        try super.setUpWithError()
        directory = try makeIndicatorDirectory()
        linked = try linkedFixtures()
        github = FakePackFetcher()
    }

    /// A loaded set in the test's directory, as the Security Extension starting again makes one.
    ///
    /// - Returns: The set.
    /// - Throws: If it can't be made.
    private func started() throws -> SavedIndicatorSet {
        let set = try makeSavedIndicatorSet(in: directory, defaults: linked, verifier: try packVerifier(),
                                            fetcher: github)
        set.load()
        return set
    }

    /// Leave the marker a Security Extension leaves when it stops while checking packs.
    ///
    /// - Parameter files: The packs it was checking.
    /// - Throws: If the marker can't be written.
    private func stopWhileChecking(_ files: Data...) throws {
        let digests = files.map(IndicatorPackUpdates.digest(of:))
        try writeIndicatorFile(try JSONEncoder().encode(digests),
                               named: IndicatorPackUpdates.checkingLayout.fileName, in: directory)
    }

    /// The refusal a passed-over pack gets.
    private let passedOver = IndicatorPackRefusal.stoppedTheExtension.description

    /// A check leaves no marker behind once it's answered, whatever it came to.
    func testNoMarkerIsLeftOnceAPackIsAnsweredFor() throws {
        let set = try started()
        XCTAssertEqual(set.send(IndicatorRequest(.checkPack, pack: try releaseFixture(2).file)).status, .ok)
        XCTAssertEqual(set.send(IndicatorRequest(.checkPack, pack: Data("nope".utf8))).status, .invalid)
        XCTAssertEqual(names(in: directory), ["indicators.json"])
        XCTAssertEqual(set.queue.sync { set.checking }, [])
    }

    /// A pack the Security Extension stopped over once is tried again. After the second time it's passed over,
    /// from GitHub and from a file, without being read. A later pack is still taken.
    func testAPackThatStoppedItTwiceIsPassedOver() throws {
        let file = try releaseFixture(2).file
        github.offer([("pack-2", file)])
        try stopWhileChecking(file)
        let once = try started()
        XCTAssertEqual(names(in: directory), ["indicator-updates.json", "indicators.json"], "The marker is gone")
        XCTAssertEqual(once.send(IndicatorRequest(.checkPack)).pack?.sequence, 2, "Once isn't enough")

        try stopWhileChecking(file)
        let twice = try started()
        for request in [IndicatorRequest(.checkPack), IndicatorRequest(.installPack),
                        IndicatorRequest(.installPack, pack: file)] {
            let reply = twice.send(request)
            XCTAssertEqual(reply.status, .invalid)
            XCTAssertEqual(reply.failure, passedOver)
        }
        let list = twice.send(IndicatorRequest(.list))
        XCTAssertEqual(list.indicators, linked)
        XCTAssertEqual(list.pack?.problem, passedOver)
        XCTAssertNil(list.pack?.available)

        github.offer([("pack-3", try releaseFixture(3).file), ("pack-2", file)])
        twice.queue.sync { twice.lastFetch = nil }
        XCTAssertEqual(twice.send(IndicatorRequest(.installPack)).pack?.sequence, 3)
        XCTAssertEqual(try started().send(IndicatorRequest(.installPack, pack: file)).status, .invalid)
    }

    /// An installed pack whose load never finished counts once against that file, so a look that finds the same
    /// pack again has one more try.
    func testAPackWhoseLoadNeverFinishedCountsOnce() throws {
        let file = try releaseFixture(2).file
        github.offer([("pack-2", file)])
        XCTAssertEqual(try started().send(IndicatorRequest(.installPack, pack: file)).status, .ok)
        try writeIndicatorFile(Data(), named: IndicatorPackFile.loadingLayout.fileName, in: directory)
        let setAside = try started()
        XCTAssertEqual(setAside.send(IndicatorRequest(.list)).pack?.source, .linked)
        XCTAssertEqual(setAside.queue.sync { setAside.updates.stopped }, [IndicatorPackUpdates.digest(of: file): 1])

        try stopWhileChecking(file)
        XCTAssertEqual(try started().send(IndicatorRequest(.checkPack)).failure, passedOver)
    }

    /// The count is kept across restarts, only packs that stopped it twice are remembered once there are many, and
    /// a marker that isn't a list of packs counts against none.
    func testTheCountIsKept() throws {
        var updates = IndicatorPackUpdates()
        updates.strike(["a", "a", "b"])
        XCTAssertEqual(updates.stopped, ["a": 1, "b": 1], "A pack named twice in one marker stopped it once")
        updates.strike(["a"])
        XCTAssertTrue(updates.isPassedOver("a"))
        XCTAssertFalse(updates.isPassedOver("b"))
        XCTAssertEqual(IndicatorPackUpdates(updates.encoded())?.stopped, ["a": 2, "b": 1])
        updates.strike((0..<40).map { "pack \($0)" })
        XCTAssertEqual(updates.stopped, ["a": 2])

        try writeIndicatorFile(Data("nope".utf8), named: IndicatorPackUpdates.checkingLayout.fileName, in: directory)
        let set = try started()
        XCTAssertEqual(set.queue.sync { set.updates.stopped }, [:])
        XCTAssertEqual(names(in: directory), ["indicators.json"])
    }
}
