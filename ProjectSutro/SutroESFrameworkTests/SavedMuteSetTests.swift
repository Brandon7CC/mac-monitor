//
//  SavedMuteSetTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - The saved mute set
/// Pins the Security Extension's saved mute set: first run, who may change it, what a change must look like, that
/// every change is saved before followers hear of it, and how a damaged, newer or untrustworthy file is handled.
final class SavedMuteSetTests: XCTestCase {
    private var store = MuteStore(directory: URL(fileURLWithPath: "/nonexistent"))
    private var saved = SavedMuteSet(testing: MuteStore(directory: URL(fileURLWithPath: "/nonexistent")))
    /// Every set handed to the follower, in order.
    private var followed: [MuteList] = []
    /// Who changed each set how, in order.
    private var changes: [MuteSetChange] = []
    private var subscription: MuteSubscription?
    
    /// A saved set in a fresh directory, followed by the test.
    ///
    /// - Throws: If the directory can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        store = try makeMuteStore()
        saved = SavedMuteSet(testing: store)
        followed = []
        changes = []
    }
    
    /// Start following the saved set.
    ///
    /// - Returns: The set when following started.
    @discardableResult
    private func follow() -> MuteList {
        let (list, subscription) = saved.follow { [weak self] list, change in
            self?.followed.append(list)
            self?.changes.append(change)
        }
        self.subscription = subscription
        return list
    }
    
    /// Send a request and wait for the reply.
    ///
    /// - Parameters:
    ///   - request: The request.
    ///   - access: What the caller may do.
    /// - Returns: The reply.
    private func send(_ request: MuteRequest, access: MuteAccess = .write) -> MuteReply {
        send(request.encoded(), access: access)
    }
    
    /// Send raw request bytes and wait for the reply.
    ///
    /// - Parameters:
    ///   - data: The bytes.
    ///   - access: What the caller may do.
    /// - Returns: The reply.
    private func send(_ data: Data, access: MuteAccess = .write) -> MuteReply {
        let replied = expectation(description: "reply")
        var reply: MuteReply?
        saved.handle(data, access: access, caller: "Test") { data in
            reply = MuteReply.decode(data)
            replied.fulfill()
        }
        wait(for: [replied], timeout: 5)
        return reply ?? MuteReply(status: .unsupported, mutes: [], problems: ["No reply."])
    }
    
    /// One entry.
    ///
    /// - Parameters:
    ///   - path: Its path.
    ///   - events: Its event names. None means every event.
    /// - Returns: The entry, matched literally.
    private func entry(_ path: String, _ events: [String] = []) -> MuteFile.Entry {
        MuteFile.Entry(path: path, type: "ES_MUTE_PATH_TYPE_LITERAL", events: events)
    }
    
    /// The first run starts from Mac Monitor's default set and saves it.
    func testFirstRunSavesTheDefaultSet() {
        saved.load()
        XCTAssertEqual(savedFile(in: store), MuteFile(.testDefault).encoded())
        let reply = send(MuteRequest(.list))
        XCTAssertEqual(reply.status, .ok)
        XCTAssertEqual(reply.mutes, MuteFile(.testDefault).mutes)
        XCTAssertNil(reply.notice)
    }
    
    /// Following hands back the set now, then each change once it's saved, with who made it how, until the
    /// subscription is released.
    func testFollowersGetEachSavedChange() {
        XCTAssertEqual(follow(), .testDefault)
        let reply = send(MuteRequest(.add, [entry("/usr/bin/yes")]))
        XCTAssertEqual(reply.status, .ok)
        XCTAssertTrue(reply.changed)
        var expected = MuteList.testDefault
        expected.add(PathMute(path: "/usr/bin/yes", type: ES_MUTE_PATH_TYPE_LITERAL))
        XCTAssertEqual(followed, [expected])
        XCTAssertEqual(changes, [MuteSetChange(caller: "Test", added: 1, removed: 0, changed: 0,
                                               mutes: expected.count)])
        XCTAssertEqual(savedFile(in: store), MuteFile(expected).encoded())
        
        subscription = nil
        _ = send(MuteRequest(.remove, [entry("/usr/bin/yes")]))
        saved.waitUntilIdle()
        XCTAssertEqual(followed, [expected])
        XCTAssertEqual(savedFile(in: store), MuteFile(.testDefault).encoded())
    }
    
    /// Remove, replace and reset each save and hand on the set they make.
    func testRemoveReplaceAndReset() {
        follow()
        XCTAssertEqual(send(MuteRequest(.replace, [entry("/a", ["ES_EVENT_TYPE_NOTIFY_OPEN",
                                                               "ES_EVENT_TYPE_NOTIFY_CLOSE"])])).mutes,
                       [entry("/a", ["ES_EVENT_TYPE_NOTIFY_CLOSE", "ES_EVENT_TYPE_NOTIFY_OPEN"])])
        XCTAssertEqual(send(MuteRequest(.remove, [entry("/a", ["ES_EVENT_TYPE_NOTIFY_OPEN"])])).mutes,
                       [entry("/a", ["ES_EVENT_TYPE_NOTIFY_CLOSE"])])
        XCTAssertEqual(send(MuteRequest(.remove, [entry("/a")])).mutes, [])
        XCTAssertEqual(send(MuteRequest(.reset)).mutes, MuteFile(.testDefault).mutes)
        XCTAssertEqual(followed.map(\.count), [1, 1, 0, MuteList.testDefault.count])
        XCTAssertEqual(savedFile(in: store), MuteFile(.testDefault).encoded())
    }
    
    /// A caller that may only read gets the set, and every change is refused without touching the file or followers.
    func testReadAccessCanOnlyList() {
        follow()
        let before = savedFile(in: store)
        XCTAssertEqual(send(MuteRequest(.list), access: .read).status, .ok)
        for request in [MuteRequest(.add, [entry("/x")]), MuteRequest(.remove, [entry("/usr/libexec/logd")]),
                        MuteRequest(.replace), MuteRequest(.reset)] {
            let reply = send(request, access: .read)
            XCTAssertEqual(reply.status, .refused, request.operation.rawValue)
            XCTAssertEqual(reply.mutes, MuteFile(.testDefault).mutes)
        }
        XCTAssertEqual(savedFile(in: store), before)
        XCTAssertEqual(followed, [])
    }
    
    /// A standard user's Mac Monitor gets the set, and every change is refused with its own status and sentence,
    /// without touching the file or followers. Every reply says what the caller may do.
    func testStandardUsersCanOnlyList() {
        follow()
        let before = savedFile(in: store)
        let list = send(MuteRequest(.list), access: .standardUser)
        XCTAssertEqual(list.status, .ok)
        XCTAssertEqual(list.access, .standardUser)
        for request in [MuteRequest(.add, [entry("/x")]), MuteRequest(.remove, [entry("/usr/libexec/logd")]),
                        MuteRequest(.replace), MuteRequest(.reset)] {
            let reply = send(request, access: .standardUser)
            XCTAssertEqual(reply.status, .notAdministrator, request.operation.rawValue)
            XCTAssertEqual(reply.problems, [MuteAccess.standardUser.refusal?.problem], request.operation.rawValue)
            XCTAssertEqual(reply.access, .standardUser)
            XCTAssertEqual(reply.mutes, MuteFile(.testDefault).mutes)
        }
        XCTAssertEqual(savedFile(in: store), before)
        XCTAssertEqual(followed, [])
        XCTAssertEqual(send(MuteRequest(.list), access: .read).access, .read)
        XCTAssertEqual(send(MuteRequest(.add, [entry("/x")])).access, .write)
    }
    
    /// A mute that can't be used fails the whole request: nothing is saved or handed on.
    func testInvalidMutesChangeNothing() {
        follow()
        let before = savedFile(in: store)
        let requests = [MuteRequest(.add, [entry("/ok"), entry("relative")]),
                        MuteRequest(.add, [entry("/a", ["ES_EVENT_TYPE_AUTH_OPEN"])]),
                        MuteRequest(.replace, [entry("/a", ["ES_EVENT_TYPE_NOTIFY_FUTURE"])]),
                        MuteRequest(.remove, [entry("/usr/libexec/logd", ["ES_EVENT_TYPE_NOTIFY_OPEN"])])]
        for request in requests {
            let reply = send(request)
            XCTAssertEqual(reply.status, .invalid, request.operation.rawValue)
            XCTAssertEqual(reply.problems.count, 1)
        }
        XCTAssertTrue(send(requests[3]).problems[0].contains("Remove it, then add it back"))
        XCTAssertEqual(savedFile(in: store), before)
        XCTAssertEqual(followed, [])
    }
    
    /// A request that changes nothing writes nothing.
    ///
    /// - Throws: If the file's attributes can't be read.
    func testAnUnchangedSetWritesNothing() throws {
        follow()
        let attributes = { try FileManager.default.attributesOfItem(atPath: self.store.fileURL.path) }
        let before = try attributes()
        let reply = send(MuteRequest(.add, [entry("/usr/libexec/logd")]))
        XCTAssertEqual(reply.status, .ok)
        XCTAssertFalse(reply.changed)
        XCTAssertFalse(send(MuteRequest(.remove, [entry("/not/muted")])).changed)
        let after = try attributes()
        XCTAssertEqual(before[.systemFileNumber] as? Int, after[.systemFileNumber] as? Int)
        XCTAssertEqual(before[.modificationDate] as? Date, after[.modificationDate] as? Date)
        XCTAssertEqual(followed, [])
    }
    
    /// A save that fails changes nothing and hands nothing on.
    func testAFailedSaveChangesNothing() {
        follow()
        chmod(store.directory.path, 0o500)
        defer { chmod(store.directory.path, 0o700) }
        let reply = send(MuteRequest(.add, [entry("/x")]))
        XCTAssertEqual(reply.status, .storageFailed)
        XCTAssertEqual(reply.mutes, MuteFile(.testDefault).mutes)
        XCTAssertEqual(followed, [])
    }
    
    /// A file from a newer Mac Monitor is kept: the default set applies, changes are refused, and Reset overwrites
    /// it with Mac Monitor's default set.
    ///
    /// - Throws: If the file can't be written.
    func testANewerFileIsReadOnlyUntilReset() throws {
        let newer = #"{"version": 2, "mutes": []}"#
        try writeSavedFile(newer, in: store)
        XCTAssertEqual(follow(), .testDefault)
        let list = send(MuteRequest(.list))
        XCTAssertTrue(list.notice?.contains("newer Mac Monitor") == true)
        XCTAssertEqual(send(MuteRequest(.add, [entry("/x")])).status, .readOnly)
        XCTAssertEqual(savedFile(in: store), Data(newer.utf8))
        
        let reset = send(MuteRequest(.reset))
        XCTAssertEqual(reset.status, .ok)
        XCTAssertTrue(reset.changed)
        XCTAssertNil(reset.notice)
        XCTAssertEqual(savedFile(in: store), MuteFile(.testDefault).encoded())
        XCTAssertEqual(send(MuteRequest(.add, [entry("/x")])).status, .ok)
    }
    
    /// A damaged file is moved aside, the default set restored and saved, and the notice stays until the next change.
    ///
    /// - Throws: If the file can't be written.
    func testADamagedFileIsRecoveredWithANotice() throws {
        try writeSavedFile("nope", in: store)
        XCTAssertEqual(follow(), .testDefault)
        XCTAssertEqual(savedFile(in: store), MuteFile(.testDefault).encoded())
        let notice = send(MuteRequest(.list)).notice ?? ""
        XCTAssertTrue(notice.contains("couldn't be read"), notice)
        XCTAssertTrue(notice.contains(MuteStore.unreadableFileName), notice)
        XCTAssertNotNil(send(MuteRequest(.list)).notice)
        XCTAssertNil(send(MuteRequest(.add, [entry("/x")])).notice)
    }
    
    /// A directory others can write is never written through: the default set applies and every change fails.
    func testAnUntrustedDirectoryRefusesEveryChange() {
        chmod(store.directory.path, 0o777)
        defer { chmod(store.directory.path, 0o700) }
        XCTAssertEqual(follow(), .testDefault)
        XCTAssertEqual(send(MuteRequest(.list)).status, .ok)
        XCTAssertNotNil(send(MuteRequest(.list)).notice)
        XCTAssertEqual(send(MuteRequest(.add, [entry("/x")])).status, .storageFailed)
        XCTAssertEqual(send(MuteRequest(.reset)).status, .storageFailed)
        XCTAssertNil(savedFile(in: store))
        XCTAssertEqual(followed, [])
    }
    
    /// A request too large, from a newer Mac Monitor, or not a request at all is answered with the set as it stands.
    func testRequestsThatCantBeRead() {
        follow()
        XCTAssertEqual(send(Data(count: MuteLimits.maxFileBytes + 1)).status, .invalid)
        XCTAssertEqual(send(Data("nope".utf8)).status, .invalid)
        XCTAssertEqual(send(Data(#"{"version": 1, "operation": "frobnicate"}"#.utf8)).status, .unsupported)
        let newer = send(Data(#"{"version": 2, "operation": "list"}"#.utf8))
        XCTAssertEqual(newer.status, .unsupported)
        XCTAssertEqual(newer.mutes, MuteFile(.testDefault).mutes)
        XCTAssertEqual(followed, [])
    }
}
