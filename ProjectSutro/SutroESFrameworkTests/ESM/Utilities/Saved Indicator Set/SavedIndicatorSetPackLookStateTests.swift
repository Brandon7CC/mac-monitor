//
//  SavedIndicatorSetPackLookStateTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/16/26.
//

import XCTest
import os
@testable import SutroESFramework


// MARK: - What a look leaves behind
/// Pins what the Security Extension remembers across looks for a newer pack that overlap, fail or are asked for by
/// someone who may only read: the daily look keeps its own time, a failed look forgets nothing, a look that an
/// install overtook isn't a problem, and what's told is never more than a few lines. GitHub is a
/// ``FakePackFetcher``, and the build links in ``XCTestCase/linkedFixtures()``.
final class SavedIndicatorSetPackLookStateTests: XCTestCase {
    private var directory: URL!
    private var linked: [Indicator] = []
    private var github = FakePackFetcher()
    private var clock = TestClock()

    /// A fresh directory, GitHub and clock.
    ///
    /// - Throws: If the directory can't be created or a fixture is missing.
    override func setUpWithError() throws {
        try super.setUpWithError()
        directory = try makeIndicatorDirectory()
        linked = try linkedFixtures()
        github = FakePackFetcher()
        clock = TestClock()
    }

    /// A loaded set in the test's directory, which asks the test's GitHub and reads the test's clock.
    ///
    /// - Returns: The set.
    /// - Throws: If it can't be made.
    private func loaded() throws -> SavedIndicatorSet {
        let clock = clock
        let set = try makeSavedIndicatorSet(in: directory, defaults: linked, verifier: try packVerifier(),
                                            fetcher: github, clock: { clock.now })
        set.load()
        return set
    }

    /// Offer the release fixtures on GitHub, newest first.
    ///
    /// - Parameter sequences: The releases, such as 3 and 2.
    /// - Throws: If a fixture is missing.
    private func offer(_ sequences: Int...) throws {
        github.offer(try sequences.map { ("pack-\($0)", try releaseFixture($0).file) })
    }

    /// Someone who may only list can't put off the daily look by asking for one of their own: in the automatic mode
    /// the pack is still installed when the day is up.
    func testALookSomeoneAskedForDoesNotPutOffTheDailyLook() throws {
        try offer(2)
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.setPackMode, mode: .automatic)).status, .ok)
        set.lookIfDueAndWait()
        XCTAssertEqual(set.send(IndicatorRequest(.list)).pack?.sequence, 2)

        try offer(3, 2)
        for _ in 0..<3 {
            clock.advance(by: IndicatorPackUpdates.checkInterval / 3)
            XCTAssertEqual(set.send(IndicatorRequest(.checkPack), access: .list).pack?.sequence, 3)
            set.lookIfDueAndWait()
        }
        let list = set.send(IndicatorRequest(.list))
        XCTAssertEqual(list.pack?.sequence, 3, "A day after the last daily look, it looked again and installed")
        XCTAssertEqual(list.pack?.source, .installed)
    }

    /// A daily look GitHub didn't answer is tried again at the next hour, not a day later.
    func testADailyLookGitHubDidNotAnswerIsTriedAgainSoon() throws {
        let set = try loaded()
        github.answer(IndicatorPackRelease.releasesURL, with: .failure(.unreachable("Offline.")))
        set.lookIfDueAndWait()
        XCTAssertEqual(set.send(IndicatorRequest(.list)).pack?.problem, "GitHub couldn't be reached. Offline.")

        try offer(2)
        clock.advance(by: 3_600)
        set.lookIfDueAndWait()
        let list = set.send(IndicatorRequest(.list))
        XCTAssertEqual(list.pack?.available, 2)
        XCTAssertNil(list.pack?.problem)
        clock.advance(by: 3_600)
        set.lookIfDueAndWait()
        XCTAssertEqual(github.listings, 2, "It was answered, so the next daily look is a day on")
    }

    /// A look GitHub doesn't answer forgets nothing: the pack an earlier look found is still out.
    func testAFailedLookKeepsThePackThatWasFound() throws {
        try offer(3)
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.checkPack)).pack?.sequence, 3)
        github.answer(IndicatorPackRelease.releasesURL, with: .success((Data("[]".utf8), 403)))
        clock.advance(by: IndicatorPackUpdates.answerLifetime)
        XCTAssertEqual(set.send(IndicatorRequest(.checkPack), access: .list).status, .unreachable)
        let list = set.send(IndicatorRequest(.list))
        XCTAssertEqual(list.pack?.available, 3)
        XCTAssertEqual(list.pack?.problem, "GitHub answered 403 for the indicator packs' releases.")
        XCTAssertEqual(try loaded().send(IndicatorRequest(.list)).pack?.available, 3, "And after a restart")
    }

    /// A look whose pack was installed while GitHub was still answering isn't a problem: there's nothing newer, and
    /// GitHub's late answer doesn't stand in for the next look.
    func testALookAnInstallOvertookFindsNothingNewer() throws {
        try offer(2)
        github.hold()
        let set = try loaded()
        var overtaken: IndicatorReply?
        let replied = expectation(description: "The look's reply")
        set.handle(IndicatorRequest(.checkPack).encoded(), access: .write, caller: "Test") { data in
            overtaken = IndicatorReply.decode(data)
            replied.fulfill()
        }
        set.waitUntilIdle()
        XCTAssertEqual(set.send(IndicatorRequest(.installPack, pack: try releaseFixture(2).file)).status, .ok)
        github.release()
        wait(for: [replied], timeout: 30)
        XCTAssertEqual(overtaken?.status, .ok, overtaken?.failure ?? "")
        XCTAssertEqual(overtaken?.pack?.sequence, 2)
        XCTAssertEqual(overtaken?.pack?.source, .installed)

        let next = set.send(IndicatorRequest(.checkPack))
        XCTAssertEqual(next.status, .ok, next.failure ?? "")
        let list = set.send(IndicatorRequest(.list))
        XCTAssertNil(list.pack?.problem)
        XCTAssertNil(list.pack?.available)
    }

    /// The mode can be changed while the set is read-only, so someone can turn the daily look off. The automatic
    /// mode can't install then, so its daily look says a pack is out rather than failing unseen.
    func testAReadOnlySetStillTakesTheMode() throws {
        try writeIndicatorFile(Data(#"{"version": 99, "saved": {"entries": []}}"#.utf8), in: directory)
        try offer(2)
        let set = try loaded()
        XCTAssertTrue(set.send(IndicatorRequest(.list)).readOnly)
        XCTAssertEqual(set.send(IndicatorRequest(.setPackMode, mode: .automatic)).status, .ok)
        set.lookIfDueAndWait()
        var list = set.send(IndicatorRequest(.list))
        XCTAssertEqual(list.pack?.available, 2)
        XCTAssertEqual(list.pack?.sequence, 0)
        XCTAssertEqual(set.send(IndicatorRequest(.setPackMode, mode: .off)).status, .ok)
        list = set.send(IndicatorRequest(.list))
        XCTAssertEqual(list.pack?.mode, .off)
        XCTAssertEqual(set.send(IndicatorRequest(.setPackMode, mode: .off), access: .list).status, .refused)
    }

    /// A mode that can't be kept isn't said to be set: the reply says it couldn't be saved, and the mode stays.
    func testAModeThatCannotBeKeptIsNotSet() throws {
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.list)).pack?.mode, .notify)
        chmod(directory.path, 0o500)
        defer { chmod(directory.path, 0o700) }
        let reply = set.send(IndicatorRequest(.setPackMode, mode: .off))
        XCTAssertEqual(reply.status, .storageFailed)
        XCTAssertEqual(reply.pack?.mode, .notify)
        XCTAssertEqual(set.send(IndicatorRequest(.list)).pack?.mode, .notify)
    }

    /// An install that says which release it expects brings that one or nothing: when GitHub has a later one by
    /// then, it's refused, and the later one is what's out.
    func testAnInstallBringsOnlyTheReleaseItExpects() throws {
        try offer(2)
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.checkPack)).pack?.sequence, 2)
        try offer(3, 2)
        clock.advance(by: IndicatorPackUpdates.answerLifetime)
        let refused = set.send(IndicatorRequest(.installPack, expecting: 2))
        XCTAssertEqual(refused.status, .invalid)
        XCTAssertEqual(refused.failure,
                       "Pack 3 is out now, not pack 2, which was checked. Check again before installing.")
        let list = set.send(IndicatorRequest(.list))
        XCTAssertEqual(list.indicators, linked)
        XCTAssertEqual(list.pack?.available, 3)
        XCTAssertNil(list.pack?.problem)
        XCTAssertEqual(set.send(IndicatorRequest(.installPack, expecting: 3)).pack?.sequence, 3)

        let file = try releaseFixture(2).file
        XCTAssertEqual(set.send(IndicatorRequest(.installPack, pack: file, expecting: 5)).status, .invalid)
    }

    /// The daily look installs only if the mode is still automatic once the pack is verified: turned to notify
    /// while GitHub was asked, it says the pack is out and installs nothing.
    func testTheDailyLookInstallsOnlyWhileTheModeIsAutomatic() throws {
        try offer(2)
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.setPackMode, mode: .automatic)).status, .ok)
        github.hold()
        let done = DispatchSemaphore(value: 0)
        set.queue.async { set.lookIfDue { done.signal() } }
        set.waitUntilIdle()
        XCTAssertEqual(set.send(IndicatorRequest(.setPackMode, mode: .notify)).status, .ok)
        github.release()
        XCTAssertEqual(done.wait(timeout: .now() + 30), .success)
        let list = set.send(IndicatorRequest(.list))
        XCTAssertEqual(list.indicators, linked)
        XCTAssertEqual(list.pack?.source, .linked)
        XCTAssertEqual(list.pack?.available, 2)
    }

    /// Packs are verified one at a time, and only so many may wait. A request that brings one more is told to try
    /// again, and the rest are answered once their turn comes.
    func testOnlySoManyPacksWaitToBeVerified() throws {
        let gate = DispatchSemaphore(value: 0)
        let root = try packRoot()
        let verifier = IndicatorPackVerifier(requirement: .developerID(team: Self.packTeam, anchoredAt: root),
                                             anchors: [root]) {
            gate.wait()
            gate.signal()
            return Self.packClock
        }
        let set = try makeSavedIndicatorSet(in: directory, defaults: linked, verifier: verifier)
        set.load()
        let request = IndicatorRequest(.checkPack, pack: try releaseFixture(2).file).encoded()
        let statuses = OSAllocatedUnfairLock(initialState: [MuteReply.Status]())
        let total = SavedIndicatorSet.maxVerifications + 3
        let replied = expectation(description: "Every reply")
        replied.expectedFulfillmentCount = total
        for _ in 0..<total {
            set.handle(request, access: .list, caller: "Test") { data in
                statuses.withLock { $0.append(IndicatorReply.decode(data)?.status ?? .unsupported) }
                replied.fulfill()
            }
        }
        set.waitUntilIdle()
        XCTAssertEqual(statuses.withLock { $0 }, [.unreachable, .unreachable, .unreachable],
                       "Those past the limit were told to try again at once")
        gate.signal()
        wait(for: [replied], timeout: 30)
        XCTAssertEqual(statuses.withLock { $0 }.filter { $0 == .ok }.count, SavedIndicatorSet.maxVerifications)
        XCTAssertEqual(set.send(request, access: .list).status, .ok, "And there's room again")
    }

    /// A pack is verified with the network only for a caller that may change the set. For one that may only read,
    /// its certificate's dates still count.
    func testOnlyACallerThatMayChangeTheSetHasTheNetworkAsked() throws {
        let set = try loaded()
        let request = IndicatorRequest(.checkPack, pack: try releaseFixture(2).file)
        for (access, usesNetwork) in [(MuteAccess.write, true), (.list, false), (.read, false)] {
            let pack = try set.queue.sync { try set.packRequest(request, access: access, caller: "Test").get() }
            XCTAssertEqual(pack?.usesNetwork, usesNetwork, access.rawValue)
        }
        let expired = try packVerifier(clock: Self.packDate("2047-01-01T00:00:00Z"))
        guard case .expired? = packRefusal(try releaseFixture(2).file, .checking, by: expired) else {
            return XCTFail("A check without the network took an expired certificate")
        }
        XCTAssertNil(packRefusal(try releaseFixture(2).file, .checking, by: try packVerifier()))
    }

    /// What a file from GitHub says about itself is never told at length: a problem is a few lines at most, in
    /// every reply and in what's kept.
    func testAProblemIsNeverLong() throws {
        let long = String(repeating: "A", count: 200_000)
        let file = try JSONSerialization.data(withJSONObject: ["format": long, "version": 1])
        github.offer([("pack-7", file)])
        let set = try loaded()
        let reply = set.send(IndicatorRequest(.checkPack))
        XCTAssertEqual(reply.status, .invalid)
        XCTAssertLessThanOrEqual(reply.failure?.count ?? 0, 500)
        let list = set.send(IndicatorRequest(.list))
        XCTAssertLessThanOrEqual(list.pack?.problem?.count ?? 0, 500)
        XCTAssertEqual(list.pack?.problem?.hasPrefix("The pack wasn't installed. The file is “AAAA"), true)
        XCTAssertLessThan(list.encoded().count, 20_000)
    }
}
