//
//  SavedIndicatorSetPackLookTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/16/26.
//

import XCTest
import os
@testable import SutroESFramework


// MARK: - Looking on GitHub for a newer pack
/// Pins how the Security Extension looks for a newer indicator pack: what a check and an install without a file do
/// with what GitHub has, how often GitHub is asked, who may ask, what each mode does once a day, and what's kept.
/// GitHub is a ``FakePackFetcher``, and the build links in ``XCTestCase/linkedFixtures()``.
final class SavedIndicatorSetPackLookTests: XCTestCase {
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
    /// - Parameter sequence: Which release the build links in: none unless given.
    /// - Returns: The set.
    /// - Throws: If it can't be made.
    private func loaded(sequence: Int = 0) throws -> SavedIndicatorSet {
        let clock = clock
        let set = try makeSavedIndicatorSet(in: directory, defaults: linked, sequence: sequence,
                                            verifier: try packVerifier(), fetcher: github, clock: { clock.now })
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

    /// The clock's time, as a status says it.
    private var now: String {
        ISO8601DateFormatter().string(from: clock.now)
    }

    /// A check finds the newest pack, says what installing it would do, and changes nothing but what's remembered:
    /// that it's out, and when GitHub was asked. Every reply says so from then on.
    func testACheckFindsANewerPack() throws {
        try offer(3, 2)
        let set = try loaded()
        let pack = try releaseFixture(3).pack
        let check = set.send(IndicatorRequest(.checkPack))
        XCTAssertEqual(check.status, .ok, check.failure ?? "")
        XCTAssertFalse(check.changed)
        XCTAssertEqual(check.indicators, pack.indicators)
        XCTAssertEqual(check.pack?.sequence, 3)
        XCTAssertEqual(github.asked, [IndicatorPackRelease.releasesURL, FakePackFetcher.download(of: "pack-3")])

        let list = set.send(IndicatorRequest(.list))
        XCTAssertEqual(list.indicators, linked)
        XCTAssertEqual(list.pack, IndicatorPackStatus(sequence: 0, source: .linked, mode: .notify, checked: now,
                                                      available: 3))
        XCTAssertEqual(names(in: directory), ["indicator-updates.json", "indicators.json"])
    }

    /// A check's reply passes on what the pack's release says of it, and for as long as GitHub's answer stands. An
    /// install's reply and a list's don't, and a reply about a pack that came in a file has none to pass on.
    func testACheckPassesOnTheReleasesNotes() throws {
        let pack = try releaseFixture(2).file
        github.offer([("pack-2", pack)], notes: "## Pack 2\n- A new indicator.")
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.checkPack)).notes, "## Pack 2\n- A new indicator.")
        XCTAssertEqual(set.send(IndicatorRequest(.checkPack)).notes, "## Pack 2\n- A new indicator.")
        XCTAssertEqual(github.listings, 1)
        XCTAssertNil(set.send(IndicatorRequest(.list)).notes)
        XCTAssertNil(set.send(IndicatorRequest(.checkPack, pack: pack)).notes)
        let installed = set.send(IndicatorRequest(.installPack))
        XCTAssertTrue(installed.changed)
        XCTAssertNil(installed.notes)
    }

    /// With nothing later on GitHub, a check replies with the set as it stands and downloads nothing.
    func testNoNewerPackDownloadsNothing() throws {
        try offer(2)
        let set = try loaded(sequence: 2)
        let check = set.send(IndicatorRequest(.checkPack))
        XCTAssertEqual(check.status, .ok)
        XCTAssertEqual(check.indicators, linked)
        XCTAssertEqual(check.pack, IndicatorPackStatus(sequence: 2, source: .linked, linked: 2, mode: .notify,
                                                       checked: now))
        XCTAssertEqual(github.asked, [IndicatorPackRelease.releasesURL])

        github.offer([])
        clock.advance(by: IndicatorPackUpdates.answerLifetime)
        XCTAssertEqual(set.send(IndicatorRequest(.installPack)).changed, false)
    }

    /// An install without a file installs the newest pack from GitHub, and nothing is out any more.
    func testAnInstallWithoutAFileInstallsTheNewest() throws {
        try offer(3, 2)
        let set = try loaded()
        let (file, pack) = try releaseFixture(3)
        let reply = set.send(IndicatorRequest(.installPack))
        XCTAssertEqual(reply.status, .ok, reply.failure ?? "")
        XCTAssertTrue(reply.changed)
        XCTAssertEqual(reply.indicators, pack.indicators)
        XCTAssertEqual(reply.pack?.sequence, 3)
        XCTAssertEqual(reply.pack?.source, .installed)
        XCTAssertNil(reply.pack?.available)
        XCTAssertEqual(indicatorFile(named: IndicatorPackFile.installedLayout.fileName, in: directory), file)

        let again = set.send(IndicatorRequest(.installPack))
        XCTAssertEqual(again.status, .ok)
        XCTAssertFalse(again.changed, "GitHub has nothing later")
        XCTAssertEqual(github.listings, 2, "What GitHub answered before the install isn't reused after it")
    }

    /// A check then an install within five minutes asks GitHub once. After five minutes GitHub is asked again.
    func testGitHubIsAskedOnceEveryFiveMinutes() throws {
        try offer(2)
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.checkPack)).pack?.sequence, 2)
        XCTAssertEqual(set.send(IndicatorRequest(.checkPack), access: .list).pack?.sequence, 2)
        XCTAssertEqual(github.asked.count, 2)
        let first = now

        try offer(3, 2)
        clock.advance(by: IndicatorPackUpdates.answerLifetime - 1)
        XCTAssertEqual(set.send(IndicatorRequest(.checkPack)).pack?.sequence, 2, "The last answer stands")
        XCTAssertEqual(set.send(IndicatorRequest(.list)).pack?.checked, first)
        clock.advance(by: 1)
        XCTAssertEqual(set.send(IndicatorRequest(.checkPack)).pack?.sequence, 3)
        XCTAssertEqual(github.asked.count, 4)
        XCTAssertEqual(set.send(IndicatorRequest(.list)).pack?.checked, now)
    }

    /// Requests that arrive while GitHub is being asked share its one answer.
    func testRequestsShareOneAnswer() throws {
        try offer(2)
        github.hold()
        let set = try loaded()
        let replied = expectation(description: "Three replies")
        replied.expectedFulfillmentCount = 3
        let sequences = OSAllocatedUnfairLock(initialState: [Int]())
        for _ in 0..<3 {
            set.handle(IndicatorRequest(.checkPack).encoded(), access: .write, caller: "Test") { data in
                sequences.withLock { $0.append(IndicatorReply.decode(data)?.pack?.sequence ?? -1) }
                replied.fulfill()
            }
        }
        set.waitUntilIdle()
        XCTAssertEqual(github.asked, [IndicatorPackRelease.releasesURL])
        github.release()
        wait(for: [replied], timeout: 30)
        XCTAssertEqual(sequences.withLock { $0 }, [2, 2, 2])
        XCTAssertEqual(github.asked.count, 2)
    }

    /// GitHub not answering, answering something else, or sending a pack that's too large is unreachable, never "no
    /// newer pack". The reason is told until a look goes well, and it's remembered that GitHub was asked.
    func testGitHubNotAnswering() throws {
        let set = try loaded()
        let failures: [(FakePackFetcher.Answer, String)] = [
            (.failure(.unreachable("Offline.")), "GitHub couldn't be reached. Offline."),
            (.success((Data("[]".utf8), 404)), "GitHub answered 404 for the indicator packs' releases."),
            (.success((Data("nope".utf8), 200)), "GitHub's list of the indicator packs' releases couldn't be read."),
        ]
        for (answer, failure) in failures {
            github.answer(IndicatorPackRelease.releasesURL, with: answer)
            clock.advance(by: IndicatorPackUpdates.answerLifetime)
            for operation in [IndicatorRequest.Operation.checkPack, .installPack] {
                let reply = set.send(IndicatorRequest(operation))
                XCTAssertEqual(reply.status, .unreachable)
                XCTAssertEqual(reply.failure, failure)
                XCTAssertEqual(reply.indicators, linked)
            }
            XCTAssertEqual(set.send(IndicatorRequest(.list)).pack?.problem, failure)
            XCTAssertEqual(set.send(IndicatorRequest(.list)).pack?.checked, now)
        }
        try offer(2)
        github.answer(FakePackFetcher.download(of: "pack-2"), with: .success((Data(), 503)))
        clock.advance(by: IndicatorPackUpdates.answerLifetime)
        XCTAssertEqual(set.send(IndicatorRequest(.checkPack)).failure,
                       "GitHub answered 503 for the indicator pack's download.")

        try offer(2)
        clock.advance(by: IndicatorPackUpdates.answerLifetime)
        XCTAssertEqual(set.send(IndicatorRequest(.checkPack)).status, .ok)
        XCTAssertNil(set.send(IndicatorRequest(.list)).pack?.problem)
        XCTAssertEqual(names(in: directory), ["indicator-updates.json", "indicators.json"])
    }

    /// A pack from GitHub is verified like any other: one that isn't signed by the fixtures' Developer ID is refused,
    /// nothing is installed, nothing is said to be out, and the reason is told.
    func testAPackFromGitHubIsVerified() throws {
        github.offer([("pack-7", try fixture("indicator-pack-not-developer-id.json"))])
        let set = try loaded()
        let refusal = "The pack wasn't installed. It isn't signed with a Developer ID Application certificate from "
            + "Apple."
        for operation in [IndicatorRequest.Operation.checkPack, .installPack] {
            let reply = set.send(IndicatorRequest(operation))
            XCTAssertEqual(reply.status, .invalid)
            XCTAssertEqual(reply.failure, refusal)
        }
        let list = set.send(IndicatorRequest(.list))
        XCTAssertNil(list.pack?.available)
        XCTAssertEqual(list.pack?.problem, refusal)
        XCTAssertEqual(list.indicators, linked)

        github.offer([("pack-9", try releaseFixture(2).file)])
        clock.advance(by: IndicatorPackUpdates.answerLifetime)
        let mislabeled = set.send(IndicatorRequest(.installPack))
        XCTAssertEqual(mislabeled.pack?.sequence, 2, "The pack's own signed sequence counts, not its tag")
    }

    /// Anyone who may list the set may ask for a look, but only a caller that may change it installs. While the mode
    /// is off, only such a caller has GitHub asked at all.
    func testWhoMayAsk() throws {
        try offer(2)
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.checkPack), access: .read).pack?.sequence, 2)
        XCTAssertEqual(set.send(IndicatorRequest(.installPack), access: .list).status, .refused)
        XCTAssertEqual(set.send(IndicatorRequest(.list)).indicators, linked)

        XCTAssertEqual(set.send(IndicatorRequest(.setPackMode, mode: .off)).status, .ok)
        clock.advance(by: IndicatorPackUpdates.answerLifetime)
        let asked = github.asked.count
        for access in [MuteAccess.read, .list] {
            let reply = set.send(IndicatorRequest(.checkPack), access: access)
            XCTAssertEqual(reply.status, .refused)
            XCTAssertEqual(reply.failure, """
                Indicator pack updates are off on this Mac, so only someone who may change the indicators can look \
                for one.
                """)
        }
        XCTAssertEqual(github.asked.count, asked, "GitHub wasn't asked")
        XCTAssertEqual(set.send(IndicatorRequest(.checkPack)).pack?.sequence, 2)
        XCTAssertEqual(set.send(IndicatorRequest(.installPack)).changed, true)
    }

    /// Only a caller that may change the set changes the mode. It's notify until someone does, it needs naming, and
    /// it's kept across a restart.
    func testTheMode() throws {
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.list)).pack?.mode, .notify)
        for access in [MuteAccess.read, .list] {
            XCTAssertEqual(set.send(IndicatorRequest(.setPackMode, mode: .automatic), access: access).status, .refused)
        }
        XCTAssertEqual(set.send(IndicatorRequest(.setPackMode)).failure, "Say which mode: off, notify or auto.")
        XCTAssertEqual(set.send(IndicatorRequest(.list)).pack?.mode, .notify)

        let reply = set.send(IndicatorRequest(.setPackMode, mode: .automatic))
        XCTAssertEqual(reply.status, .ok)
        XCTAssertFalse(reply.changed, "The set didn't change")
        XCTAssertEqual(reply.pack?.mode, .automatic)
        XCTAssertEqual(set.send(IndicatorRequest(.list)).pack?.mode, .automatic, "A list isn't answered from before")
        XCTAssertEqual(try loaded().send(IndicatorRequest(.list)).pack?.mode, .automatic)
    }

    /// Once a day, the notify mode looks and remembers a newer pack without installing it, the automatic mode
    /// installs it, and off doesn't look. Within a day of the last look, nothing looks.
    func testTheDailyLook() throws {
        try offer(2)
        let set = try loaded()
        set.lookIfDueAndWait()
        var list = set.send(IndicatorRequest(.list))
        XCTAssertEqual(list.pack?.available, 2)
        XCTAssertEqual(list.pack?.checked, now)
        XCTAssertEqual(list.indicators, linked, "Notify installs nothing")
        XCTAssertEqual(github.listings, 1)

        clock.advance(by: IndicatorPackUpdates.checkInterval - 1)
        set.lookIfDueAndWait()
        XCTAssertEqual(github.listings, 1, "Not a day yet")

        XCTAssertEqual(set.send(IndicatorRequest(.setPackMode, mode: .off)).status, .ok)
        clock.advance(by: IndicatorPackUpdates.checkInterval)
        set.lookIfDueAndWait()
        XCTAssertEqual(github.listings, 1, "Off never looks on its own")

        XCTAssertEqual(set.send(IndicatorRequest(.setPackMode, mode: .automatic)).status, .ok)
        set.lookIfDueAndWait()
        list = set.send(IndicatorRequest(.list))
        XCTAssertEqual(github.listings, 2)
        XCTAssertEqual(list.pack?.sequence, 2)
        XCTAssertEqual(list.pack?.source, .installed)
        XCTAssertNil(list.pack?.available)
        XCTAssertEqual(list.indicators, try releaseFixture(2).pack.indicators)

        try offer(3, 2)
        clock.advance(by: IndicatorPackUpdates.checkInterval)
        set.lookIfDueAndWait()
        XCTAssertEqual(set.send(IndicatorRequest(.list)).pack?.sequence, 3)
    }

    /// What a look found and when GitHub was asked are kept across a restart. A pack that was out is no longer news
    /// once it, or a later one, is installed or linked into the build.
    func testWhatALookFoundIsKept() throws {
        try offer(2)
        XCTAssertEqual(try loaded().send(IndicatorRequest(.checkPack)).pack?.sequence, 2)
        let checked = now
        clock.advance(by: 3_600)
        let restarted = try loaded().send(IndicatorRequest(.list))
        XCTAssertEqual(restarted.pack?.available, 2)
        XCTAssertEqual(restarted.pack?.checked, checked)
        XCTAssertEqual(github.listings, 1, "Starting again asks GitHub nothing")

        XCTAssertNil(try loaded(sequence: 2).send(IndicatorRequest(.list)).pack?.available)
        let installed = try loaded().send(IndicatorRequest(.installPack, pack: try releaseFixture(3).file))
        XCTAssertEqual(installed.status, .ok)
        XCTAssertNil(installed.pack?.available)
        XCTAssertNil(try loaded().send(IndicatorRequest(.list)).pack?.available)
    }

    /// When GitHub was last asked is kept whatever the look came to, an install included, so a restart doesn't look
    /// again before a day has passed.
    func testWhenGitHubWasAskedIsKeptAfterAnInstall() throws {
        try offer(2)
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.setPackMode, mode: .automatic)).status, .ok)
        set.lookIfDueAndWait()
        XCTAssertEqual(set.send(IndicatorRequest(.list)).pack?.sequence, 2)
        let checked = now

        clock.advance(by: 3_600)
        let restarted = try loaded()
        XCTAssertEqual(restarted.send(IndicatorRequest(.list)).pack?.checked, checked)
        restarted.lookIfDueAndWait()
        XCTAssertEqual(github.listings, 1, "Not a day yet")
    }

    /// Installing an earlier pack from a file leaves a later one that's out as news.
    func testALaterPackStaysOutAfterAnEarlierOneIsInstalled() throws {
        try offer(3)
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.checkPack)).pack?.sequence, 3)
        let reply = set.send(IndicatorRequest(.installPack, pack: try releaseFixture(2).file))
        XCTAssertEqual(reply.pack?.sequence, 2)
        XCTAssertEqual(reply.pack?.available, 3)
    }
}
