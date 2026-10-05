//
//  DefaultMuteSetTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - The default set's per-user mutes
/// Pins whose home folder Mac Monitor's default mute set mutes: the console user's, never the root Security
/// Extension's own `/var/root`, when the saved set is created or reset. With no one logged in those mutes are left out
/// and the user is told; a saved set is never rewritten except by Reset.
final class DefaultMuteSetTests: XCTestCase {
    private let alice = ConsoleUser(name: "alice", uid: 502, home: "/Users/alice")
    /// Who the saved set under test finds at the console.
    private var consoleUser: ConsoleUser?
    private var store = MuteStore(directory: URL(fileURLWithPath: "/nonexistent"))
    
    /// A fresh directory for the saved set.
    ///
    /// - Throws: If the directory can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        store = try makeMuteStore()
        consoleUser = alice
    }
    
    /// The per-user mutes for a home folder: files created and renamed in its caches, and extended attributes read
    /// from files in its Biome streams. Each folder ends in `/`, so no sibling that starts with its name is muted.
    ///
    /// - Parameter home: The home folder.
    /// - Returns: Each mute's key and events.
    private func homeMutes(in home: String) -> [MuteList.Key: MuteScope] {
        [MuteList.Key(path: home + "/Library/Caches/", type: ES_MUTE_PATH_TYPE_TARGET_PREFIX):
            .events([ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_RENAME]),
         MuteList.Key(path: home + "/Library/Biome/streams/", type: ES_MUTE_PATH_TYPE_TARGET_PREFIX):
            .events([ES_EVENT_TYPE_NOTIFY_GETEXTATTR])]
    }
    
    /// A saved set that finds ``consoleUser`` at the console each time it makes the default set.
    ///
    /// - Returns: The saved set.
    private func makeSavedSet() -> SavedMuteSet {
        SavedMuteSet(store: store, consoleUser: { [unowned self] in self.consoleUser })
    }
    
    /// Send a request with write access and wait for the reply.
    ///
    /// - Parameters:
    ///   - request: The request.
    ///   - saved: The saved set.
    /// - Returns: The reply.
    private func send(_ request: MuteRequest, to saved: SavedMuteSet) -> MuteReply? {
        var reply: MuteReply?
        saved.handle(request.encoded(), access: .write, caller: "Test") { reply = MuteReply.decode($0) }
        saved.waitUntilIdle()
        return reply
    }
    
    /// The default set mutes the console user's caches and Biome streams, and nothing of root's.
    func testTheDefaultSetMutesTheConsoleUsersHome() {
        let list = MuteList.shippedDefault(for: alice)
        for (key, scope) in homeMutes(in: "/Users/alice") {
            XCTAssertEqual(list.scopes[key], scope, key.path)
        }
        XCTAssertFalse(list.keys.contains { $0.path.hasPrefix("/var/root") })
        XCTAssertEqual(MuteList.shippedDefault(for: ConsoleUser(name: "alice", uid: 502, home: "/Users/alice/")),
                       list)
    }
    
    /// The user owns their home folder, so its mutes cover only the folders chosen: never a sibling the user makes
    /// whose name starts the same (Endpoint Security matches a prefix as a string), and never a program run from
    /// there, only the files in them.
    func testTheHomeMutesCoverOnlyTheirFolders() {
        let list = MuteList.shippedDefault(for: alice)
        for path in ["/Users/alice/Library/CachesX/f", "/Users/alice/Library/Biome/streamsX/f"] {
            XCTAssertFalse(list.keys.contains { path.hasPrefix($0.path) }, path)
        }
        for path in ["/Users/alice/Library/Caches/f", "/Users/alice/Library/Biome/streams/f"] {
            XCTAssertTrue(list.keys.contains { path.hasPrefix($0.path) }, path)
        }
        let programMutes = [ES_MUTE_PATH_TYPE_LITERAL, ES_MUTE_PATH_TYPE_PREFIX]
        XCTAssertFalse(list.keys.contains { $0.path.hasPrefix("/Users/") && programMutes.contains($0.type) })
    }
    
    /// With no one logged in, the default set is the same less the two per-user mutes. A home folder too long to
    /// mute in is left out the same way.
    func testWithoutAConsoleUserThePerUserMutesAreLeftOut() {
        let full = MuteList.shippedDefault(for: alice), bare = MuteList.shippedDefault(for: nil)
        XCTAssertEqual(Set(full.keys).subtracting(bare.keys), Set(homeMutes(in: "/Users/alice").keys))
        XCTAssertTrue(Set(bare.keys).isSubset(of: full.keys))
        XCTAssertEqual(bare.count, full.count - 2)
        XCTAssertEqual(MuteSet.homePaths("Library/Caches", in: "/" + String(repeating: "a", count: 1_100)), [])
    }
    
    /// The first run saves the default set for whoever is logged in, without a notice.
    func testTheFirstRunMutesTheConsoleUsersHome() {
        let saved = makeSavedSet()
        saved.load()
        XCTAssertEqual(savedFile(in: store), MuteFile(.shippedDefault(for: alice)).encoded())
        XCTAssertNil(send(MuteRequest(.list), to: saved)?.notice)
    }
    
    /// A first run with no one logged in leaves the per-user mutes out and says so until the next change; a Reset
    /// once someone is logged in adds them. A Reset with no one logged in says what it left out.
    func testWithNoOneLoggedInResetAddsThemLater() {
        consoleUser = nil
        let saved = makeSavedSet()
        saved.load()
        XCTAssertEqual(savedFile(in: store), MuteFile(.shippedDefault(for: nil)).encoded())
        XCTAssertEqual(send(MuteRequest(.list), to: saved)?.notice, SavedMuteSet.noConsoleUser)
        
        let leftOut = send(MuteRequest(.reset), to: saved)
        XCTAssertEqual(leftOut?.status, .ok)
        XCTAssertEqual(leftOut?.problems, [])
        XCTAssertEqual(leftOut?.notice, SavedMuteSet.noConsoleUser)
        
        consoleUser = alice
        let reset = send(MuteRequest(.reset), to: saved)
        XCTAssertEqual(reset?.status, .ok)
        XCTAssertEqual(reset?.changed, true)
        XCTAssertEqual(reset?.problems, [])
        XCTAssertNil(reset?.notice)
        XCTAssertEqual(savedFile(in: store), MuteFile(.shippedDefault(for: alice)).encoded())
    }
    
    /// A Reset with no one logged in, such as `macmonitor mute reset` over SSH at the login window, takes the
    /// per-user mutes out of a set that had them, and Path Muting keeps saying so until the next change, as after a
    /// first run.
    ///
    /// - Throws: If the set can't be saved.
    func testAResetWithNoOneLoggedInSaysSoUntilTheNextChange() throws {
        try store.save(.shippedDefault(for: alice))
        consoleUser = nil
        let saved = makeSavedSet()
        let reset = send(MuteRequest(.reset), to: saved)
        XCTAssertEqual(reset?.changed, true)
        XCTAssertEqual(reset?.problems, [])
        XCTAssertEqual(reset?.notice, SavedMuteSet.noConsoleUser)
        XCTAssertEqual(savedFile(in: store), MuteFile(.shippedDefault(for: nil)).encoded())
        XCTAssertEqual(send(MuteRequest(.list), to: saved)?.notice, SavedMuteSet.noConsoleUser)
        
        let entry = MuteFile.Entry(path: "/usr/bin/yes", type: "ES_MUTE_PATH_TYPE_LITERAL")
        XCTAssertNil(send(MuteRequest(.add, [entry]), to: saved)?.notice)
    }
    
    /// A newer file or an untrusted directory found with no one logged in, as at boot, applies the default set without
    /// the per-user mutes, and the notice says so: Reset adds them to a newer file's place, and nothing can change a
    /// set that can't be kept, so its notice says they come with the next start.
    ///
    /// - Throws: If the file can't be written.
    func testTheFallbackWithNoOneLoggedInSaysSo() throws {
        consoleUser = nil
        try writeSavedFile(#"{"version": 2, "mutes": []}"#, in: store)
        let newer = send(MuteRequest(.list), to: makeSavedSet())
        XCTAssertEqual(newer?.mutes, MuteFile(.shippedDefault(for: nil)).mutes)
        XCTAssertTrue(newer?.notice?.contains("newer Mac Monitor") == true)
        XCTAssertTrue(newer?.notice?.hasSuffix(SavedMuteSet.noConsoleUser) == true, newer?.notice ?? "")
        
        chmod(store.directory.path, 0o777)
        defer { chmod(store.directory.path, 0o700) }
        let untrusted = send(MuteRequest(.list), to: makeSavedSet())
        XCTAssertEqual(untrusted?.mutes, MuteFile(.shippedDefault(for: nil)).mutes)
        XCTAssertTrue(untrusted?.notice?.hasPrefix("Mac Monitor can't keep a saved mute set.") == true)
        XCTAssertTrue(untrusted?.notice?.hasSuffix(SavedMuteSet.noConsoleUserUntilRestart) == true,
                      untrusted?.notice ?? "")
        
        consoleUser = alice
        XCTAssertFalse(send(MuteRequest(.list), to: makeSavedSet())?.notice?.contains("No one was logged in") ?? true)
    }
    
    /// A damaged file restored with no one logged in says both.
    ///
    /// - Throws: If the file can't be written.
    func testADamagedFileRestoredWithNoOneLoggedInSaysSo() throws {
        try writeSavedFile("nope", in: store)
        consoleUser = nil
        let notice = send(MuteRequest(.list), to: makeSavedSet())?.notice ?? ""
        XCTAssertTrue(notice.hasPrefix("Your saved mute set couldn't be read."), notice)
        XCTAssertTrue(notice.hasSuffix(SavedMuteSet.noConsoleUser), notice)
    }
    
    /// A saved set, even one an earlier 2.2 build made for `/var/root`, is kept as it is whoever logs in; only Reset
    /// makes the default set again, for the console user.
    ///
    /// - Throws: If the file can't be written.
    func testASavedSetIsOnlyRewrittenByReset() throws {
        let rootDefault = MuteFile(MuteList.shippedDefault(for: ConsoleUser(name: "root", uid: 0, home: "/var/root")))
        let earlier = String(decoding: rootDefault.encoded(), as: UTF8.self)
        try writeSavedFile(earlier, in: store)
        let saved = makeSavedSet()
        let list = send(MuteRequest(.list), to: saved)
        XCTAssertEqual(list?.mutes, rootDefault.mutes)
        XCTAssertNil(list?.notice)
        XCTAssertEqual(savedFile(in: store), Data(earlier.utf8))
        
        XCTAssertEqual(send(MuteRequest(.reset), to: saved)?.mutes, MuteFile(.shippedDefault(for: alice)).mutes)
        XCTAssertEqual(savedFile(in: store), MuteFile(.shippedDefault(for: alice)).encoded())
    }
}
