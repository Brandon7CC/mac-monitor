//
//  SavedIndicatorSetPackTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/16/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Installing a signed pack
/// Pins what installing a signed indicator pack does to the Mac's set: each indicator nobody edited takes the pack's,
/// what someone changed is kept, and a pack is refused, with everything left as it was, when its signature isn't
/// accepted, its payload isn't a pack, it isn't a later release, one of its indicators can't run, or the set would be
/// past a limit with it.
///
/// The build these tests stand for links in three indicators (``XCTestCase/linkedFixtures()``): "Fixture program
/// ran" at revision 1, "Fixture quarantine removed", and "Fixture dropped", which no release has.
final class SavedIndicatorSetPackTests: XCTestCase {
    /// Every exec.
    private static let exec = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#

    private var directory: URL!
    /// The indicators the build links in.
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
    /// - Parameters:
    ///   - sequence: Which release the build links in: none unless given.
    ///   - clock: The time its verifier says.
    /// - Returns: The set.
    /// - Throws: If it can't be made.
    private func loaded(sequence: Int = 0, clock: Date = XCTestCase.packClock) throws -> SavedIndicatorSet {
        let set = try makeSavedIndicatorSet(in: directory, defaults: linked, sequence: sequence,
                                            verifier: try packVerifier(clock: clock))
        set.load()
        return set
    }

    /// A request that brings a pack's file.
    ///
    /// - Parameters:
    ///   - file: The pack's file.
    ///   - installs: Install it, or only check it?
    /// - Returns: The request.
    private func request(_ file: Data, installs: Bool = true) -> IndicatorRequest {
        IndicatorRequest(installs ? .installPack : .checkPack, pack: file)
    }

    /// A capture session keeps a sequence's open chains through a pack install when the pack didn't change the
    /// sequence, even at a new revision, and starts over for a sequence the pack changed.
    func testAPackKeepsTheOpenChainsOfASequenceItDidntChange() throws {
        var kept = sequenceIndicator(SequenceEngineTests.ordered())
        var changed = sequenceIndicator(SequenceEngineTests.ordered())
        let set = try makeSavedIndicatorSet(in: directory, defaults: linked + [kept, changed],
                                            verifier: try packVerifier())
        set.load()
        var received: [CompiledIndicators] = []
        let (first, subscription) = set.follow { received.append($0) }
        defer { subscription.cancel() }
        let chains = SessionChains(for: first)

        kept.revision = 7
        changed.rule = .sequence(SequenceEngineTests.ordered(within: 6))
        let reply = set.take(verified(try packPayload(sequence: 2, linked + [kept, changed])))
        XCTAssertEqual(reply.status, .ok, reply.failure ?? "")
        set.queue.sync {}
        let installed = try XCTUnwrap(received.last)
        let next = SessionChains(for: installed, reusing: chains)
        /// A session's tables are in its set's order.
        let table = { (chains: SessionChains, set: CompiledIndicators, id: UUID) in
            set.sequences.firstIndex { $0.id == id }.map { chains.tables[$0] }
        }
        XCTAssertNotNil(table(chains, first, kept.id))
        XCTAssertTrue(table(next, installed, kept.id) === table(chains, first, kept.id), "Its open chains carry over")
        XCTAssertNotNil(table(next, installed, changed.id))
        XCTAssertFalse(table(next, installed, changed.id) === table(chains, first, changed.id),
                       "A changed sequence starts over")
    }

    /// A release replaces the build's indicators: one whose rule it changed takes the new rule, one it dropped goes,
    /// and one it adds arrives as the pack has it, here off. The reply says which release is installed and lists its
    /// indicators, and its file is kept exactly as signed, beside the saved set.
    func testAReleaseReplacesTheBuildsIndicators() throws {
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.list)).pack,
                       IndicatorPackStatus(sequence: 0, source: .linked, mode: .notify))
        let (file, pack) = try releaseFixture(2)
        let reply = set.send(request(file))
        XCTAssertEqual(reply.status, .ok, reply.failure ?? "")
        XCTAssertTrue(reply.changed)
        XCTAssertEqual(reply.indicators, pack.indicators)
        XCTAssertEqual(reply.baseline, pack.indicators)
        XCTAssertEqual(reply.pack, IndicatorPackStatus(sequence: 2, source: .installed,
                                                       published: "2026-11-16T00:00:00Z",
                                                       commit: String(repeating: "2", count: 40), mode: .notify))
        XCTAssertEqual(reply.problems, [])
        XCTAssertEqual(set.current.count, 2, "The third is off")
        XCTAssertEqual(indicatorFile(named: IndicatorPackFile.installedLayout.fileName, in: directory), file)
        XCTAssertEqual(names(in: directory), ["indicator-pack.json", "indicators.json"], "No marker is left")
        XCTAssertEqual(try savedIndicators(in: directory, defaults: pack.indicators), pack.indicators)
        XCTAssertEqual(set.send(IndicatorRequest(.list)), reply.with(changed: false), "A list says the same")
    }

    /// What someone changed is kept. An indicator turned off stays off and takes the pack's rule. One whose rule was
    /// edited stays as edited, and so does an edited one the pack dropped, as someone's own. One of someone's own
    /// stays.
    func testWhatSomeoneChangedIsKept() throws {
        let set = try loaded()
        var edited = linked[1], kept = linked[2]
        edited.rule = .event(edited.predicate! + " AND process.pid > 1")
        kept.rule = .event(kept.predicate! + " AND process.pid > 1")
        let mine = ownIndicator("Mine", Self.exec)
        XCTAssertEqual(set.send(IndicatorRequest(.setEnabled, ids: [linked[0].id], enabled: false)).status, .ok)
        XCTAssertEqual(set.send(IndicatorRequest(.add, indicators: [edited, kept, mine])).status, .ok)

        let pack = try releaseFixture(2).pack
        let reply = set.send(request(try releaseFixture(2).file))
        XCTAssertEqual(reply.status, .ok, reply.failure ?? "")
        var off = pack.indicators[0]
        off.isEnabled = false
        XCTAssertEqual(reply.indicators, [off, edited, kept, mine, pack.indicators[2]])
        let hits = Dictionary(uniqueKeysWithValues: set.current.ruleHits.map { ($0.id, $0) })
        XCTAssertEqual(hits[edited.id]?.edited, true, "It's the pack's, edited on this Mac")
        XCTAssertEqual(hits[kept.id]?.isDefault, false, "The pack doesn't have it, so it's someone's own now")
        XCTAssertEqual(hits[mine.id]?.isDefault, false)
    }

    /// A deleted indicator stays deleted, whatever the pack does to it, and one nobody touched that the pack dropped
    /// goes.
    func testADeletedIndicatorStaysDeleted() throws {
        let set = try loaded()
        XCTAssertEqual(set.send(IndicatorRequest(.remove, ids: [linked[0].id])).status, .ok)
        let pack = try releaseFixture(2).pack
        let reply = set.send(request(try releaseFixture(2).file))
        XCTAssertEqual(reply.status, .ok, reply.failure ?? "")
        XCTAssertEqual(reply.indicators, [pack.indicators[1], pack.indicators[2]])
        XCTAssertEqual(reply.baseline, pack.indicators, "Restore Defaults would bring it back")
        XCTAssertEqual(set.send(IndicatorRequest(.reset)).indicators, pack.indicators)
    }

    /// A later release installs over an earlier one. Its entry that needs a newer Mac Monitor is counted, and not
    /// run.
    func testALaterReleaseInstallsOverAnEarlierOne() throws {
        let set = try loaded()
        XCTAssertEqual(set.send(request(try releaseFixture(2).file)).status, .ok)
        let (file, pack) = try releaseFixture(3)
        let reply = set.send(request(file))
        XCTAssertEqual(reply.status, .ok, reply.failure ?? "")
        XCTAssertEqual(reply.indicators, pack.indicators)
        XCTAssertEqual(reply.pack?.sequence, 3)
        XCTAssertEqual(reply.pack?.needsNewer, 1)
        XCTAssertEqual(pack.newer.map(\.name), ["Fixture from a newer Mac Monitor"])
        XCTAssertEqual(indicatorFile(named: IndicatorPackFile.installedLayout.fileName, in: directory), file)
    }

    /// A release that isn't later than the indicators the Mac has is refused, so a pack signed once can't bring back
    /// a rule a later one fixed: an earlier release, the installed one again, and one no later than the build's.
    func testAReleaseThatIsNotLaterIsRefused() throws {
        let set = try loaded()
        let latest = try releaseFixture(3)
        XCTAssertEqual(set.send(request(latest.file)).status, .ok)
        let before = set.send(IndicatorRequest(.list))

        let earlier = set.send(request(try releaseFixture(2).file))
        XCTAssertEqual(earlier.status, .invalid)
        XCTAssertEqual(earlier.failure, "Pack 2 is older than pack 3, which is installed.")
        let again = set.send(request(latest.file))
        XCTAssertEqual(again.status, .invalid)
        XCTAssertEqual(again.failure, "Pack 3 is already installed.")
        XCTAssertEqual(set.send(IndicatorRequest(.list)), before)
        XCTAssertEqual(indicatorFile(named: IndicatorPackFile.installedLayout.fileName, in: directory), latest.file)

        directory = try makeIndicatorDirectory()
        let floor = try loaded(sequence: 2).send(request(try releaseFixture(2).file))
        XCTAssertEqual(floor.status, .invalid)
        XCTAssertEqual(floor.failure,
                       "Pack 2 isn't newer than the indicators this Mac Monitor came with (pack 2).")
        XCTAssertEqual(names(in: directory), ["indicators.json"])
    }

    /// A pack whose signature isn't accepted is refused before anything in it is read: one changed after it was
    /// signed, one signed by a certificate that isn't a Developer ID Application one, and one whose certificate has
    /// expired by this Mac's clock.
    func testAPackWhoseSignatureIsNotAcceptedIsRefused() throws {
        let set = try loaded()
        let changed = try packFile("indicator-pack-2.json") { object in
            guard var bytes = (object["payload"] as? String).flatMap({ Data(base64Encoded: $0) }) else { return }
            bytes[bytes.count / 2] ^= 1
            object["payload"] = bytes.base64EncodedString()
        }
        let refusals = [
            (changed, "The pack wasn't installed. The pack's signature doesn't verify, so the pack changed after it "
                + "was signed."),
            (try fixture("indicator-pack-not-developer-id.json"),
             "The pack wasn't installed. It isn't signed with a Developer ID Application certificate from Apple."),
        ]
        for (file, failure) in refusals {
            let reply = set.send(request(file))
            XCTAssertEqual(reply.status, .invalid)
            XCTAssertEqual(reply.failure, failure)
        }
        let expired = try loaded(clock: Self.packDate("2047-01-01T00:00:00Z")).send(request(try releaseFixture(2).file))
        XCTAssertEqual(expired.status, .invalid)
        XCTAssertEqual(expired.failure?.hasPrefix("The pack wasn't installed. The certificate “"), true,
                       expired.failure ?? "")
        XCTAssertEqual(set.send(IndicatorRequest(.list)).indicators, linked)
        XCTAssertEqual(names(in: directory), ["indicators.json"])
    }

    /// A signed payload that isn't a pack this build installs is refused: one with no indicators, one without a core
    /// identity it names, and one with an identity it retires.
    func testASignedPayloadThatIsNotAPackIsRefused() throws {
        let set = try loaded()
        let empty = set.send(request(try fixture("indicator-pack.json")))
        XCTAssertEqual(empty.status, .invalid)
        XCTAssertEqual(empty.failure,
                       "The pack is signed, but it isn't one this Mac Monitor installs. It has no indicators.")

        let missing = UUID()
        let noCore = set.take(verified(try packPayload(sequence: 2, linked, core: [missing])))
        XCTAssertEqual(noCore.failure, "The pack is signed, but it isn't one this Mac Monitor installs. It doesn't "
                       + "have the core indicator \(missing.uuidString).")
        let retired = set.take(verified(try packPayload(sequence: 2, linked, retired: [linked[2].id])))
        XCTAssertEqual(retired.failure, "The pack is signed, but it isn't one this Mac Monitor installs. It has the "
                       + "retired indicator \(linked[2].id.uuidString).")
        XCTAssertEqual(set.send(IndicatorRequest(.list)).indicators, linked)
        XCTAssertEqual(names(in: directory), ["indicators.json"])
    }

    /// A pack with an indicator this build should run but can't compile is refused whole. The same indicator saying
    /// it needs a newer Mac Monitor is kept, and not run.
    func testAPackWithAnIndicatorThisBuildCannotRunIsRefused() throws {
        let set = try loaded()
        var regex = ownIndicator("Needs MATCHES", #"event.exec != nil AND process.executable.path MATCHES ".*sh""#)
        let refused = set.take(verified(try packPayload(sequence: 2, linked + [regex])))
        XCTAssertEqual(refused.status, .invalid)
        XCTAssertEqual(refused.failure?.hasPrefix("The pack wasn't installed, because this Mac Monitor can't run its "
                                                   + "indicator “Needs MATCHES”. "), true, refused.failure ?? "")
        XCTAssertEqual(set.send(IndicatorRequest(.list)).indicators, linked)

        regex.minEngine = ReleaseVersion(9, 0, 0)
        let installed = set.take(verified(try packPayload(sequence: 2, linked + [regex])))
        XCTAssertEqual(installed.status, .ok, installed.failure ?? "")
        XCTAssertEqual(installed.indicators, linked + [regex])
        XCTAssertEqual(installed.pack?.needsNewer, 1)
        XCTAssertEqual(installed.problems.map(\.id), [regex.id])
        XCTAssertEqual(set.current.count, 3)
    }

    /// A pack that would leave the Mac with more indicators than the Security Extension keeps is refused: here the
    /// set is full, the pack adds one, and the one it drops was edited, so it stays. The Mac's own are off, so they
    /// aren't past the most rules on one event type.
    func testAPackThatPutsTheSetPastALimitIsRefused() throws {
        let set = try loaded()
        var kept = linked[2]
        kept.rule = .event(kept.predicate! + " AND process.pid > 1")
        let own = (0..<IndicatorLimits.maxIndicators - linked.count).map { number in
            var mine = ownIndicator("Mine \(number)", Self.exec)
            mine.isEnabled = false
            return mine
        }
        XCTAssertEqual(set.send(IndicatorRequest(.add, indicators: [kept] + own)).status, .ok)

        let reply = set.send(request(try releaseFixture(2).file))
        XCTAssertEqual(reply.status, .invalid)
        XCTAssertEqual(reply.failure?.hasPrefix("The pack wasn't installed, because this Mac's indicators would be "
                                                 + "past a limit with it. It has 2049 indicators."), true,
                       reply.failure ?? "")
        XCTAssertEqual(reply.pack?.sequence, 0)
        XCTAssertEqual(names(in: directory), ["indicators.json"])
    }

    /// Only a caller that may change the set installs a pack, and it's refused before the pack is looked at. Anyone
    /// who may list the set may check one.
    func testOnlyACallerThatMayChangeTheSetInstalls() throws {
        let set = try loaded()
        let file = try releaseFixture(2).file
        for access in [MuteAccess.read, .list] {
            let reply = set.send(request(file), access: access)
            XCTAssertEqual(reply.status, .refused, access.rawValue)
            XCTAssertEqual(reply.access, access)
            XCTAssertEqual(set.send(request(Data("not a pack".utf8)), access: access).status, .refused)
            XCTAssertEqual(set.send(request(file, installs: false), access: access).status, .ok, access.rawValue)
        }
        XCTAssertEqual(names(in: directory), ["indicators.json"])
    }

    /// A check says what installing would do, the set, its problems and the release as they would be, and changes
    /// nothing. A pack that wouldn't be installed is refused as an install refuses it.
    func testACheckChangesNothing() throws {
        let set = try loaded()
        let (file, pack) = try releaseFixture(2)
        let before = set.send(IndicatorRequest(.list))
        let check = set.send(request(file, installs: false))
        XCTAssertEqual(check.status, .ok, check.failure ?? "")
        XCTAssertFalse(check.changed)
        XCTAssertEqual(check.indicators, pack.indicators)
        XCTAssertEqual(check.baseline, pack.indicators)
        XCTAssertEqual(check.pack?.sequence, 2)
        XCTAssertEqual(set.send(IndicatorRequest(.list)), before)
        XCTAssertEqual(before.indicators, linked)
        XCTAssertEqual(names(in: directory), ["indicators.json"])

        let refused = set.send(request(try fixture("indicator-pack-not-developer-id.json"), installs: false))
        XCTAssertEqual(refused.status, .invalid)
        XCTAssertEqual(refused.indicators, linked)
    }

    /// A request to check or install that brings no pack is invalid for a set that never looks on GitHub for one.
    func testARequestWithoutAPackIsInvalidWithNothingToAsk() throws {
        let set = try loaded()
        for operation in [IndicatorRequest.Operation.checkPack, .installPack] {
            let reply = set.send(IndicatorRequest(operation))
            XCTAssertEqual(reply.status, .invalid)
            XCTAssertEqual(reply.failure,
                           "The request brings no pack, and this Security Extension doesn't look for one.")
        }
    }

    /// Every capture session following the set gets the set a pack makes, once.
    func testFollowersGetTheSetAPackMakes() throws {
        let set = try loaded()
        var received: [CompiledIndicators] = []
        let (first, subscription) = set.follow { received.append($0) }
        XCTAssertEqual(first.count, 3)
        XCTAssertEqual(set.send(request(try releaseFixture(2).file)).status, .ok)
        XCTAssertEqual(received.map(\.count), [2])
        XCTAssertTrue(received.first === set.current)
        XCTAssertEqual(set.send(request(try releaseFixture(2).file)).status, .invalid)
        XCTAssertEqual(received.count, 1, "A refused pack hands nothing over")
        subscription.cancel()
    }

    /// The set is read-only when a newer Mac Monitor saved it, and a pack isn't installed then.
    func testAReadOnlySetInstallsNoPack() throws {
        try writeIndicatorFile(Data(#"{"version": 99, "saved": {"entries": []}}"#.utf8), in: directory)
        let set = try loaded()
        let reply = set.send(request(try releaseFixture(2).file))
        XCTAssertEqual(reply.status, .readOnly)
        XCTAssertNil(indicatorFile(named: IndicatorPackFile.installedLayout.fileName, in: directory))
    }
}


// MARK: - Replies
private extension IndicatorReply {
    /// - Parameter changed: Whether it says the set changed.
    /// - Returns: The reply, saying so.
    func with(changed: Bool) -> IndicatorReply {
        var reply = self
        reply.changed = changed
        return reply
    }
}
