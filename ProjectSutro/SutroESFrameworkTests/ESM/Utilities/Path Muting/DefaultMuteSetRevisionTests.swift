//
//  DefaultMuteSetRevisionTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import CryptoKit
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Default set revisions and upgrades
/// Pins how a saved mute set follows Mac Monitor's default set across upgrades: each revision describes exactly what
/// changed, a set no one changed is updated when it loads, and a set someone changed is only offered the merge, which
/// keeps their changes.
///
/// The fixtures are the saved sets 3.0 wrote for `/Users/alice` on macOS 14 and later, with and without Xcode's
/// mutes.
final class DefaultMuteSetRevisionTests: XCTestCase {
    private let alice = "/Users/alice"
    private var store = MuteStore(directory: URL(fileURLWithPath: "/nonexistent"))

    /// The default set's digest at each revision, for `/Users/alice` without Xcode's mutes on macOS 14 and later.
    private let digests = [2: "51c99f84bd57fd33ea774dd42c6791b53103c8dff8558216fcc27633417aa72c",
                           3: "7b8d618ed0e247eeadb4f1e8ed90e9b013aad496f55b821214a2ae7c68e8e77f",
                           4: "f7dc6dbd389bc7db5d7377cf6c6241e38e27cd17b327b280695d0ec61ea9ae1d"]

    /// A fresh directory for the saved set.
    ///
    /// - Throws: If the directory can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        try XCTSkipUnless(ProcessInfo.processInfo.isOperatingSystemAtLeast(.init(majorVersion: 14, minorVersion: 0,
                                                                                 patchVersion: 0)),
                          "The fixtures have the XPC mutes macOS 14 added.")
        store = try makeMuteStore()
    }

    /// A 3.0 saved set.
    ///
    /// - Parameter xcode: With Xcode's mutes.
    /// - Returns: Its list.
    /// - Throws: If the fixture can't be read.
    private func set30(xcode: Bool) throws -> MuteList {
        let file = try MuteFile.decode(try fixture(xcode ? "mutes-3.0.0-alice-xcode.json" : "mutes-3.0.0-alice.json"))
        XCTAssertNil(file.defaultsRevision)
        return try file.list(.saved).list
    }

    /// The current default set for `/Users/alice`.
    ///
    /// - Parameter xcode: With Xcode's mutes.
    /// - Returns: The set.
    private func current(xcode: Bool) -> MuteList {
        MuteList(MuteSet.default(home: alice, mutesXcode: xcode).pathMutes)
    }

    // MARK: Revisions

    /// Walking the current default set back to revision 1 gives exactly the set 3.0 saved.
    func testRevisionOneIsTheSet30Saved() throws {
        for xcode in [false, true] {
            let walkedBack = MuteList.shippedDefault(home: alice, mutesXcode: xcode, revision: 1)
            XCTAssertEqual(walkedBack.difference(to: try set30(xcode: xcode)), MuteListDifference(added: [],
                           removed: [], changed: []), "Xcode \(xcode)")
        }
        XCTAssertEqual(MuteList.shippedDefault(home: alice, mutesXcode: false, revision: MuteSet.currentRevision),
                       current(xcode: false))
    }

    /// The newest revision describes the default set as it is: changing the default set without adding a revision
    /// fails here, before any saved set could be compared with the wrong base.
    func testTheNewestRevisionDescribesTheDefaultSet() {
        XCTAssertEqual(MuteSet.revisions.map(\.number), Array(2...MuteSet.currentRevision))
        let digest = SHA256.hash(data: MuteFile(current(xcode: false)).encoded())
            .map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(digest, digests[MuteSet.currentRevision], """
            The default mute set changed. Add a revision to MuteSet.revisions with exactly what changed, then pin its \
            digest here.
            """)
    }

    // MARK: Planning

    /// A 3.0 set no one changed becomes the current default set. Xcode's mutes are dropped when root no longer owns
    /// Xcode, but never added: a set without them may be one whose user unmuted Xcode.
    func testAnUnchangedSetBecomesTheCurrentDefault() throws {
        for (xcode, now) in [(false, false), (true, true), (true, false), (false, true)] {
            let plan = try XCTUnwrap(MuteSetUpgrade.plan(for: try set30(xcode: xcode), revision: 1, mutesXcode: now))
            XCTAssertTrue(plan.wasDefault, "Xcode \(xcode) then, \(now) now")
            XCTAssertEqual(plan.merged, current(xcode: xcode && now), "Xcode \(xcode) then, \(now) now")
            XCTAssertEqual(plan.revision, 1)
        }
        let atLoginWindow = MuteList.shippedDefault(home: nil, mutesXcode: false, revision: 1)
        let plan = try XCTUnwrap(MuteSetUpgrade.plan(for: atLoginWindow, revision: 1, mutesXcode: false))
        XCTAssertTrue(plan.wasDefault)
        XCTAssertEqual(plan.merged, MuteList(MuteSet.default(home: nil, mutesXcode: false).pathMutes))
    }

    /// Revision 3 adds closes to the mute of a home folder's caches, a per-user mute, so it's walked back for that
    /// home folder: revision 2's set mutes creates and renames there, an unchanged one becomes the current default
    /// set, and a changed one gets the closes and keeps its change.
    func testRevisionThreeMutesClosesInTheCaches() throws {
        let caches = MuteList.Key(path: alice + "/Library/Caches/", type: ES_MUTE_PATH_TYPE_TARGET_PREFIX)
        let two = MuteList.shippedDefault(home: alice, mutesXcode: false, revision: 2)
        XCTAssertEqual(two.scopes[caches], .events([ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_RENAME]))
        XCTAssertEqual(current(xcode: false).scopes[caches],
                       .events([ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_CLOSE]))
        XCTAssertNil(MuteList.shippedDefault(home: nil, mutesXcode: false, revision: 2).scopes[caches])

        let unchanged = try XCTUnwrap(MuteSetUpgrade.plan(for: two, revision: 2, mutesXcode: false))
        XCTAssertTrue(unchanged.wasDefault)
        XCTAssertEqual(unchanged.merged, current(xcode: false))

        var changed = two
        try changed.remove(PathMute(path: "/usr/libexec/logd", type: ES_MUTE_PATH_TYPE_LITERAL))
        let merged = try XCTUnwrap(MuteSetUpgrade.plan(for: changed, revision: 2, mutesXcode: false))
        XCTAssertFalse(merged.wasDefault)
        XCTAssertEqual(merged.merged.scopes[caches], current(xcode: false).scopes[caches])
        XCTAssertFalse(merged.merged.keys.contains { $0.path == "/usr/libexec/logd" })
    }

    /// Revision 4 mutes closes, renames and setmodes in the folder system_installd unpacks system software packages
    /// in. Revision 3's set has no mute there, and an unchanged one becomes the current default set.
    func testRevisionFourMutesTheSystemInstallersSandboxes() throws {
        let sandboxes = MuteList.Key(path: "/Library/Apple/System/Library/InstallerSandboxes/",
                                     type: ES_MUTE_PATH_TYPE_TARGET_PREFIX)
        let three = MuteList.shippedDefault(home: alice, mutesXcode: false, revision: 3)
        XCTAssertNil(three.scopes[sandboxes])
        XCTAssertEqual(current(xcode: false).scopes[sandboxes],
                       .events([ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_SETMODE]))
        XCTAssertFalse(current(xcode: false).keys.contains { $0.path.hasPrefix("/Library/InstallerSandboxes") })
        let plan = try XCTUnwrap(MuteSetUpgrade.plan(for: three, revision: 3, mutesXcode: false))
        XCTAssertTrue(plan.wasDefault)
        XCTAssertEqual(plan.merged, current(xcode: false))
    }

    /// A set at the current revision, or a newer one, has nothing to upgrade.
    func testACurrentSetHasNothingToUpgrade() {
        XCTAssertNil(MuteSetUpgrade.plan(for: current(xcode: false), revision: MuteSet.currentRevision))
        XCTAssertNil(MuteSetUpgrade.plan(for: MuteList(), revision: MuteSet.currentRevision + 1))
    }

    /// A 3.0 set first saved on macOS 13, without the XPC connect mutes, is still found unchanged on macOS 14.
    func testASetSavedOnMacOS13IsStillUnchanged() throws {
        var macOS13 = try set30(xcode: false)
        for path in ["/usr/sbin/bluetoothd", "/usr/libexec/airportd"] {
            try macOS13.remove(PathMute(path: path, type: ES_MUTE_PATH_TYPE_LITERAL,
                                        events: [ES_EVENT_TYPE_NOTIFY_XPC_CONNECT]))
        }
        XCTAssertNotEqual(macOS13, try set30(xcode: false))
        let plan = try XCTUnwrap(MuteSetUpgrade.plan(for: macOS13, revision: 1, mutesXcode: false))
        XCTAssertTrue(plan.wasDefault)
        XCTAssertEqual(plan.merged, current(xcode: false))
    }

    /// A set saved without a revision is compared with every revision. One 3.0 rewrote after a downgrade is closest
    /// to the current set, so nothing the user removed under 3.1 is offered back.
    func testASetWithoutARevisionGetsTheClosestOne() throws {
        var downgraded = current(xcode: false)
        try downgraded.remove(PathMute(path: "/dev/ttys", type: ES_MUTE_PATH_TYPE_TARGET_PREFIX))
        XCTAssertNil(MuteSetUpgrade.plan(for: downgraded, revision: nil, mutesXcode: false))
        let plan = try XCTUnwrap(MuteSetUpgrade.plan(for: try set30(xcode: false), revision: nil, mutesXcode: false))
        XCTAssertTrue(plan.wasDefault)
        XCTAssertEqual(plan.revision, 1)
    }

    /// A changed set keeps what the user added and removed, and gains what the default set added since. A mute the
    /// default set dropped goes, and a path the user unmuted gets back only the events the default set added to it.
    func testAChangedSetKeepsItsChanges() throws {
        var saved = try set30(xcode: false)
        let yes = PathMute(path: "/usr/bin/yes", type: ES_MUTE_PATH_TYPE_LITERAL)
        saved.add(yes)
        try saved.remove(PathMute(path: "/usr/libexec/logd", type: ES_MUTE_PATH_TYPE_LITERAL))
        try saved.remove(PathMute(path: "/usr/libexec/xpcproxy", type: ES_MUTE_PATH_TYPE_LITERAL))
        let plan = try XCTUnwrap(MuteSetUpgrade.plan(for: saved, revision: 1, mutesXcode: false))
        XCTAssertFalse(plan.wasDefault)
        let merged = plan.merged
        func scope(_ path: String, _ type: es_mute_path_type_t) -> MuteScope? {
            merged.scopes[MuteList.Key(path: path, type: type)]
        }
        XCTAssertEqual(scope(yes.path, yes.type), .allEvents)
        XCTAssertNil(scope("/usr/libexec/logd", ES_MUTE_PATH_TYPE_LITERAL))
        XCTAssertEqual(scope("/usr/libexec/xpcproxy", ES_MUTE_PATH_TYPE_LITERAL),
                       .events([ES_EVENT_TYPE_NOTIFY_XPC_CONNECT]))
        XCTAssertEqual(scope("/private/var/log/com.apple.xpc.launchd/launchd.log", ES_MUTE_PATH_TYPE_TARGET_LITERAL),
                       .events([ES_EVENT_TYPE_NOTIFY_CLOSE]))
        guard case .events(let cfprefsd)? = scope("/usr/sbin/cfprefsd", ES_MUTE_PATH_TYPE_LITERAL) else {
            return XCTFail("cfprefsd isn't muted for chosen events")
        }
        XCTAssertFalse(cfprefsd.contains(ES_EVENT_TYPE_NOTIFY_RENAME))

        /// Everything else is the current default set.
        var expected = current(xcode: false)
        expected.add(yes)
        try expected.remove(PathMute(path: "/usr/libexec/logd", type: ES_MUTE_PATH_TYPE_LITERAL))
        try expected.remove(PathMute(path: "/usr/libexec/xpcproxy", type: ES_MUTE_PATH_TYPE_LITERAL))
        expected.add(PathMute(path: "/usr/libexec/xpcproxy", type: ES_MUTE_PATH_TYPE_LITERAL,
                              events: [ES_EVENT_TYPE_NOTIFY_XPC_CONNECT]))
        XCTAssertEqual(merged, expected)
    }

    /// Mutes of every event: the user's stays, and one the default set adds is taken.
    func testMergingMutesOfEveryEvent() {
        let key = (path: "/usr/bin/x", type: ES_MUTE_PATH_TYPE_LITERAL)
        let some = PathMute(path: key.path, type: key.type, events: [ES_EVENT_TYPE_NOTIFY_OPEN])
        let every = PathMute(path: key.path, type: key.type)
        let other = PathMute(path: "/usr/bin/y", type: ES_MUTE_PATH_TYPE_LITERAL)
        let mine = MuteList([every, other])
        XCTAssertEqual(mine.merging(defaultsFrom: MuteList([some]), to: MuteList()), mine)
        XCTAssertEqual(MuteList([other]).merging(defaultsFrom: MuteList([some]), to: MuteList([every])),
                       MuteList([every, other]))
        XCTAssertEqual(MuteList([some, other]).merging(defaultsFrom: MuteList([every]), to: MuteList([some])),
                       MuteList([some, other]))
    }

    // MARK: The saved set

    /// The 3.0 set this Mac would have saved, as its saved file.
    ///
    /// - Parameter change: A change the user made to it.
    /// - Returns: Its list, and the file was written.
    /// - Throws: If the fixture or file can't be read or written.
    @discardableResult
    private func write30(_ change: (inout MuteList) throws -> Void = { _ in }) throws -> MuteList {
        var list = try set30(xcode: MuteSet.ownsXcode())
        try change(&list)
        try writeSavedFile(String(decoding: MuteFile(list).encoded(), as: UTF8.self), in: store)
        return list
    }

    /// A 3.0 set no one changed is updated when it loads and saved at the current revision. The reply says what
    /// was applied, apart from the notice, so a command line change isn't asked about because of it.
    func testAnUnchangedSetIsUpdatedWhenItLoads() throws {
        try write30()
        let set = SavedMuteSet(testing: store)
        let reply = set.send(MuteRequest(.list))
        let updated = MuteList(MuteSet.default(home: alice).pathMutes)
        XCTAssertEqual(reply.mutes, MuteFile(updated).mutes)
        XCTAssertNil(reply.update)
        XCTAssertNil(reply.notice)
        XCTAssertEqual(reply.applied?.release, "3.1")
        XCTAssertEqual(savedFile(in: store), savedBytes(updated))
        XCTAssertEqual(set.send(MuteRequest(.list)).applied, reply.applied, "Said until the next change")

        let again = SavedMuteSet(testing: store).send(MuteRequest(.list))
        XCTAssertNil(again.notice)
        XCTAssertNil(again.update)
        XCTAssertNil(again.applied)
    }

    /// An update that can't be saved keeps the set as it was and says so, without offering a merge as if the user
    /// had changed it.
    func testAnUpdateThatCantBeSavedSaysSo() throws {
        try XCTSkipIf(getuid() == 0, "Root writes the read-only directory anyway.")
        let before = try write30()
        chmod(store.directory.path, 0o500)
        defer { chmod(store.directory.path, 0o700) }
        let reply = SavedMuteSet(testing: store).send(MuteRequest(.list))
        XCTAssertEqual(reply.mutes, MuteFile(before).mutes)
        XCTAssertNil(reply.update)
        XCTAssertNil(reply.applied)
        XCTAssertTrue(reply.notice?.hasPrefix("Mac Monitor couldn't update your saved mute set") == true,
                      reply.notice ?? "")
    }

    /// Declining is saved with the set: the offer says so after a restart, and the set isn't updated by itself even
    /// once it matches its base again. An update still takes it in.
    func testADeclinedUpdateIsNeverAppliedByItself() throws {
        let logd = MuteFile.Entry(path: "/usr/libexec/logd", type: "ES_MUTE_PATH_TYPE_LITERAL")
        try write30 { try $0.remove(PathMute(path: logd.path, type: ES_MUTE_PATH_TYPE_LITERAL)) }
        let set = SavedMuteSet(testing: store)
        XCTAssertEqual(set.send(MuteRequest(.decline), access: .read).status, .refused)
        XCTAssertEqual(set.send(MuteRequest(.list)).update?.declined, false)
        XCTAssertEqual(set.send(MuteRequest(.decline)).update?.declined, true)
        XCTAssertEqual(try MuteFile.decode(try XCTUnwrap(savedFile(in: store))).declinedRevision,
                       MuteSet.currentRevision)

        set.send(MuteRequest(.add, [logd]))
        let restarted = SavedMuteSet(testing: store).send(MuteRequest(.list))
        XCTAssertNil(restarted.applied)
        XCTAssertEqual(restarted.update?.declined, true)
        let update = SavedMuteSet(testing: store).send(MuteRequest(.update))
        XCTAssertTrue(update.changed)
        XCTAssertNil(try MuteFile.decode(try XCTUnwrap(savedFile(in: store))).declinedRevision)
    }

    /// A changed 3.0 set is kept as it is, and every reply offers the merge until an update takes it in. Changes
    /// made meanwhile are kept in the merge.
    func testAChangedSetIsOfferedTheMerge() throws {
        let yes = MuteFile.Entry(path: "/usr/bin/yes", type: "ES_MUTE_PATH_TYPE_LITERAL")
        let saved = try write30 { try $0.remove(PathMute(path: "/usr/libexec/logd", type: ES_MUTE_PATH_TYPE_LITERAL)) }
        let before = savedFile(in: store)
        let set = SavedMuteSet(testing: store)
        let list = set.send(MuteRequest(.list))
        XCTAssertEqual(list.mutes, MuteFile(saved).mutes)
        XCTAssertNil(list.notice)
        let offer = try XCTUnwrap(list.update)
        XCTAssertEqual(offer.revision, MuteSet.currentRevision)
        XCTAssertEqual(offer.release, "3.1")
        XCTAssertFalse(offer.added.isEmpty)
        XCTAssertTrue(offer.added.contains { $0.path == "/private/var/log/com.apple.xpc.launchd/launchd.log" })
        XCTAssertFalse(offer.added.contains { $0.path == "/usr/libexec/logd" })
        XCTAssertEqual(savedFile(in: store), before, "Only an update or Reset rewrites a changed set")

        XCTAssertEqual(set.send(MuteRequest(.add, [yes])).update?.added, offer.added)
        XCTAssertEqual(MuteStore.Loaded.saved(saved.adding(yes), warnings: [], defaultsRevision: 1),
                       try store.load(), "An add keeps the set's revision")

        let update = set.send(MuteRequest(.update))
        XCTAssertEqual(update.status, .ok)
        XCTAssertTrue(update.changed)
        XCTAssertNil(update.update)
        let merged = try MuteFile.list(from: update.mutes, .saved).list
        XCTAssertTrue(merged.keys.contains(MuteList.Key(path: yes.path, type: ES_MUTE_PATH_TYPE_LITERAL)))
        XCTAssertEqual(savedFile(in: store), savedBytes(merged))
        XCTAssertNil(SavedMuteSet(testing: store).send(MuteRequest(.list)).update)
        XCTAssertFalse(set.send(MuteRequest(.update)).changed, "Nothing left to update")
    }

    /// A caller that may only read can't update, and Reset takes the update in too.
    func testUpdatesNeedWriteAccessAndResetTakesThemIn() throws {
        try write30 { try $0.remove(PathMute(path: "/usr/libexec/logd", type: ES_MUTE_PATH_TYPE_LITERAL)) }
        let set = SavedMuteSet(testing: store)
        XCTAssertEqual(set.send(MuteRequest(.update), access: .read).status, .refused)
        XCTAssertNotNil(set.send(MuteRequest(.list)).update)
        XCTAssertNil(set.send(MuteRequest(.reset)).update)
        XCTAssertEqual(savedFile(in: store), savedBytes(.testDefault))
    }

    /// A set from a newer Mac Monitor is neither updated nor offered an update.
    func testANewerSetIsLeftAlone() throws {
        try writeSavedFile(#"{"version": 1, "defaultsRevision": 99, "mutes": []}"#, in: store)
        let reply = SavedMuteSet(testing: store).send(MuteRequest(.list))
        XCTAssertEqual(reply.mutes, [])
        XCTAssertNil(reply.update)
        XCTAssertNil(reply.notice)
    }

    // MARK: What's said

    /// The update's summary leaves out what it doesn't do, and replies from a Security Extension without updates
    /// still read.
    func testTheUpdateReads() throws {
        let entry = MuteFile.Entry(path: "/a", type: "ES_MUTE_PATH_TYPE_LITERAL")
        let update = MuteSetUpdate(revision: 2, release: "3.1", added: [entry, entry], removed: [entry],
                                   changed: [entry, entry, entry])
        XCTAssertEqual(update.summary, "adds 2 mutes, changes 3 and removes 1")
        XCTAssertEqual(MuteSetUpdate(revision: 2, release: "3.1", added: [], removed: [entry], changed: []).summary,
                       "removes 1 mute")
        XCTAssertEqual(MuteSetUpdate(revision: 2, release: "3.1", added: [], removed: [], changed: []).summary,
                       "changes nothing")
        var reply = MuteReply(status: .ok, mutes: [], update: update)
        XCTAssertEqual(MuteReply.decode(reply.encoded())?.update, update)
        reply.update = nil
        XCTAssertNil(MuteReply.decode(reply.encoded())?.update)
        let odd = Data(#"{"version": 1, "status": "ok", "update": 7}"#.utf8)
        XCTAssertNil(try XCTUnwrap(MuteReply.decode(odd)).update)
    }

    /// `macmonitor mute update` applies an offer the way the Security Extension merges it.
    func testTheCommandLineAppliesAnOfferAsTheExtensionMerges() throws {
        var saved = try set30(xcode: false)
        try saved.remove(PathMute(path: "/usr/libexec/xpcproxy", type: ES_MUTE_PATH_TYPE_LITERAL))
        let plan = try XCTUnwrap(MuteSetUpgrade.plan(for: saved, revision: 1, mutesXcode: false))
        let offer = MuteSetUpdate(from: saved, to: plan.merged, after: 1)
        XCTAssertEqual(saved.applying(offer), plan.merged)
    }
}


private extension MuteList {
    /// This list with an entry added.
    ///
    /// - Parameter entry: The entry.
    /// - Returns: The list after.
    func adding(_ entry: MuteFile.Entry) -> MuteList {
        var list = self
        list.add(contentsOf: (try? MuteFile.list(from: [entry], .saved).list) ?? MuteList())
        return list
    }
}
