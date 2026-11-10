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
/// and the user is told. A saved set is never rewritten except by Reset.
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
    
    /// Closes of terminals and the console are muted, and only for close: every process a terminal starts closes its
    /// standard streams on it. Closes of disks and serial devices stay seen, as raw disk writes matter.
    func testTerminalClosesAreMutedButDisksAndSerialDevicesAreNot() {
        let list = MuteList.shippedDefault(for: alice)
        XCTAssertEqual(list.scopes[MuteList.Key(path: "/dev/ttys", type: ES_MUTE_PATH_TYPE_TARGET_PREFIX)],
                       .events([ES_EVENT_TYPE_NOTIFY_CLOSE]))
        guard case .events(let console)? = list.scopes[MuteList.Key(path: "/dev/console",
                                                                     type: ES_MUTE_PATH_TYPE_TARGET_LITERAL)] else {
            return XCTFail("/dev/console isn't muted for chosen events")
        }
        XCTAssertTrue(console.contains(ES_EVENT_TYPE_NOTIFY_CLOSE))

        /// A target mute that would cover a path, for close or for every event.
        func closeMute(covering path: String) -> MuteList.Key? {
            list.keys.first { key in
                let covers = key.type == ES_MUTE_PATH_TYPE_TARGET_PREFIX ? path.hasPrefix(key.path)
                    : key.type == ES_MUTE_PATH_TYPE_TARGET_LITERAL && path == key.path
                guard covers else { return false }
                if case .events(let events)? = list.scopes[key] { return events.contains(ES_EVENT_TYPE_NOTIFY_CLOSE) }
                return true
            }
        }
        XCTAssertNotNil(closeMute(covering: "/dev/ttys001"))
        for path in ["/dev/rdisk3", "/dev/disk2s1", "/dev/tty.usbserial-1410", "/dev/cu.usbserial-1410", "/dev/tty"] {
            XCTAssertNil(closeMute(covering: path), path)
        }
    }

    /// swcd's mmaps of web credential JSON are muted, and nothing else of it is.
    func testSwcdMapsAreMuted() {
        let list = MuteList.shippedDefault(for: alice)
        XCTAssertEqual(list.scopes[MuteList.Key(path: "/usr/libexec/swcd", type: ES_MUTE_PATH_TYPE_LITERAL)],
                       .events([ES_EVENT_TYPE_NOTIFY_MMAP]))
    }
    
    /// The idle and install noise a Sublime Text install trace showed is muted with the narrowest type that removes
    /// it: the Secure Enclave and Bluetooth daemons' programs only as mmap targets, so their execs stay seen;
    /// logd_helper's file writes but not its mmaps, a tell of a program run for the first time; and siriactionsd's
    /// connects not at all, as they show a Shortcut running in the background.
    func testInstallNoiseIsMutedNarrowly() {
        let list = MuteList.shippedDefault(for: alice)
        func scope(_ path: String, _ type: es_mute_path_type_t) -> MuteScope? {
            list.scopes[MuteList.Key(path: path, type: type)]
        }
        let mmap: Set = [ES_EVENT_TYPE_NOTIFY_MMAP]
        for path in ["/usr/libexec/seputil", "/usr/sbin/bluetoothd",
                     "/System/Library/Caches/com.apple.coresymbolicationd/data"] {
            XCTAssertEqual(scope(path, ES_MUTE_PATH_TYPE_TARGET_LITERAL), .events(mmap), path)
        }
        XCTAssertEqual(scope("/System/Library/PrivateFrameworks/MediaAnalysis.framework/Versions/A/Resources/",
                             ES_MUTE_PATH_TYPE_TARGET_PREFIX), .events(mmap))
        guard case .events(let launchdLog)? = scope("/private/var/log/com.apple.xpc.launchd/launchd.log",
                                                    ES_MUTE_PATH_TYPE_TARGET_LITERAL) else {
            return XCTFail("launchd's log isn't muted for chosen events")
        }
        XCTAssertEqual(launchdLog, [ES_EVENT_TYPE_NOTIFY_CLOSE])

        let writes: Set = [ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_RENAME,
                           ES_EVENT_TYPE_NOTIFY_SETMODE]
        XCTAssertEqual(scope("/usr/libexec/logd_helper", ES_MUTE_PATH_TYPE_LITERAL), .events(writes))
        guard case .events(let dasd)? = scope("/usr/libexec/dasd", ES_MUTE_PATH_TYPE_LITERAL) else {
            return XCTFail("dasd isn't muted for chosen events")
        }
        XCTAssertTrue(writes.isSubset(of: dasd))
        guard case .events(let updater)? = scope("/usr/libexec/spotlightknowledged.updater",
                                                 ES_MUTE_PATH_TYPE_LITERAL) else {
            return XCTFail("spotlightknowledged.updater isn't muted for chosen events")
        }
        XCTAssertEqual(updater, [ES_EVENT_TYPE_NOTIFY_MMAP, ES_EVENT_TYPE_NOTIFY_MPROTECT])

        XCTAssertNil(scope("/usr/libexec/siriactionsd", ES_MUTE_PATH_TYPE_LITERAL))
        guard #available(macOS 14, *) else { return }
        for path in ["/usr/libexec/xpcproxy", "/System/Library/CoreServices/WiFiAgent.app/Contents/MacOS/WiFiAgent",
                     "/usr/libexec/dasd", "/usr/libexec/UserEventAgent"] {
            guard case .events(let events)? = scope(path, ES_MUTE_PATH_TYPE_LITERAL) else {
                XCTFail("\(path) isn't muted for chosen events")
                continue
            }
            XCTAssertTrue(events.contains(ES_EVENT_TYPE_NOTIFY_XPC_CONNECT), path)
            XCTAssertFalse(events.contains(ES_EVENT_TYPE_NOTIFY_EXEC), path)
        }
    }

    /// cfprefsd's renames are seen, as they're how it saves a property list, and the rest of what it does is still
    /// muted: its closes are of temporary files.
    func testCfprefsdRenamesAreSeen() {
        let list = MuteList.shippedDefault(for: alice)
        func scope(_ type: es_mute_path_type_t) -> MuteScope? {
            list.scopes[MuteList.Key(path: "/usr/sbin/cfprefsd", type: type)]
        }
        guard case .events(let literal)? = scope(ES_MUTE_PATH_TYPE_LITERAL),
              case .events(let prefix)? = scope(ES_MUTE_PATH_TYPE_PREFIX) else {
            return XCTFail("cfprefsd isn't muted for chosen events")
        }
        XCTAssertFalse(literal.contains(ES_EVENT_TYPE_NOTIFY_RENAME))
        XCTAssertFalse(prefix.contains(ES_EVENT_TYPE_NOTIFY_RENAME))
        XCTAssertTrue(prefix.contains(ES_EVENT_TYPE_NOTIFY_CLOSE))
        XCTAssertTrue(literal.contains(ES_EVENT_TYPE_NOTIFY_CREATE))
    }
    
    /// Xcode's tools are muted only when root owns Xcode. An Xcode expanded from a `.xip` belongs to whoever expanded
    /// it, so a program they put inside would run unseen. Its mutes end in `/`, so they never cover a sibling folder.
    func testXcodeIsMutedOnlyWhenRootOwnsIt() {
        let xcode = { (set: MuteSet) in set.pathMutes.filter { $0.path.hasPrefix("/Applications/Xcode") } }
        XCTAssertEqual(xcode(MuteSet.default(home: nil, mutesXcode: false)).map(\.path), [])
        let muted = xcode(MuteSet.default(home: nil, mutesXcode: true))
        XCTAssertEqual(muted.count, 3)
        for mute in muted {
            XCTAssertEqual(mute.type, ES_MUTE_PATH_TYPE_PREFIX, mute.path)
            XCTAssertTrue(mute.path.hasSuffix("/"), mute.path)
        }
    }
    
    /// Xcode counts as root's only when root owns every folder its mutes cover, and the folders above them in the
    /// bundle, and no one else can change them.
    func testOnlyAnXcodeItsOwnerAloneCanChangeCounts() throws {
        try XCTSkipIf(getuid() == 0, "The test's Xcode is root's when root runs the tests.")
        let base = try XCTUnwrap(CommandLineToolLink.realPath(try makeTemporaryDirectory(prefix: "MuteSetTests").path))
        let xcode = base + "/Xcode.app", toolchain = xcode + "/Contents/Developer/Toolchains/XcodeDefault.xctoolchain"
        for folder in [toolchain, xcode + "/Contents/SharedFrameworks"] {
            try FileManager.default.createDirectory(atPath: folder, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o755])
        }
        XCTAssertTrue(MuteSet.ownsXcode(getuid(), at: xcode))
        XCTAssertFalse(MuteSet.ownsXcode(0, at: xcode), "Owned by the user running the tests")
        XCTAssertFalse(MuteSet.ownsXcode(getuid(), at: base + "/Missing.app"))
        chmod(toolchain, 0o775)
        XCTAssertFalse(MuteSet.ownsXcode(getuid(), at: xcode), "The group can change the toolchain")
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
    
    /// A first run with no one logged in leaves the per-user mutes out and says so until the next change. A Reset
    /// once someone is logged in adds them. A Reset with no one logged in says what it left out.
    func testWithNoOneLoggedInResetAddsThemLater() {
        consoleUser = nil
        let saved = makeSavedSet()
        saved.load()
        XCTAssertEqual(savedFile(in: store), savedBytes(.shippedDefault(for: nil)))
        XCTAssertEqual(saved.send(MuteRequest(.list)).notice, SavedMuteSet.noConsoleUser)
        
        let leftOut = saved.send(MuteRequest(.reset))
        XCTAssertEqual(leftOut.status, .ok)
        XCTAssertEqual(leftOut.problems, [])
        XCTAssertEqual(leftOut.notice, SavedMuteSet.noConsoleUser)
        
        consoleUser = alice
        let reset = saved.send(MuteRequest(.reset))
        XCTAssertEqual(reset.status, .ok)
        XCTAssertEqual(reset.changed, true)
        XCTAssertEqual(reset.problems, [])
        XCTAssertNil(reset.notice)
        XCTAssertEqual(savedFile(in: store), savedBytes(.shippedDefault(for: alice)))
    }
    
    /// A Reset with no one logged in, such as `macmonitor mute reset` over SSH at the login window, takes the
    /// per-user mutes out of a set that had them, and Path Muting keeps saying so until the next change, as after a
    /// first run.
    func testAResetWithNoOneLoggedInSaysSoUntilTheNextChange() throws {
        try store.save(.shippedDefault(for: alice))
        consoleUser = nil
        let saved = makeSavedSet()
        let reset = saved.send(MuteRequest(.reset))
        XCTAssertEqual(reset.changed, true)
        XCTAssertEqual(reset.problems, [])
        XCTAssertEqual(reset.notice, SavedMuteSet.noConsoleUser)
        XCTAssertEqual(savedFile(in: store), savedBytes(.shippedDefault(for: nil)))
        XCTAssertEqual(saved.send(MuteRequest(.list)).notice, SavedMuteSet.noConsoleUser)
        
        let entry = MuteFile.Entry(path: "/usr/bin/yes", type: "ES_MUTE_PATH_TYPE_LITERAL")
        XCTAssertNil(saved.send(MuteRequest(.add, [entry])).notice)
    }
    
    /// A newer file or an untrusted directory found with no one logged in, as at boot, applies the default set without
    /// the per-user mutes, and the notice says so: Reset adds them to a newer file's place, and nothing can change a
    /// set that can't be kept, so its notice says they come with the next start.
    func testTheFallbackWithNoOneLoggedInSaysSo() throws {
        consoleUser = nil
        try writeSavedFile(#"{"version": 2, "mutes": []}"#, in: store)
        let newer = makeSavedSet().send(MuteRequest(.list))
        XCTAssertEqual(newer.mutes, MuteFile(.shippedDefault(for: nil)).mutes)
        XCTAssertTrue(newer.notice?.contains("newer Mac Monitor") == true)
        XCTAssertTrue(newer.notice?.hasSuffix(SavedMuteSet.noConsoleUser) == true, newer.notice ?? "")
        
        chmod(store.directory.path, 0o777)
        let untrusted = makeSavedSet().send(MuteRequest(.list))
        XCTAssertEqual(untrusted.mutes, MuteFile(.shippedDefault(for: nil)).mutes)
        XCTAssertTrue(untrusted.notice?.hasPrefix("Mac Monitor can't keep a saved mute set.") == true)
        XCTAssertTrue(untrusted.notice?.hasSuffix(SavedMuteSet.noConsoleUserUntilRestart) == true,
                      untrusted.notice ?? "")
        
        consoleUser = alice
        XCTAssertFalse(makeSavedSet().send(MuteRequest(.list)).notice?.contains("No one was logged in") ?? true)
    }
    
    /// A damaged file restored with no one logged in says both.
    func testADamagedFileRestoredWithNoOneLoggedInSaysSo() throws {
        try writeSavedFile("nope", in: store)
        consoleUser = nil
        let notice = makeSavedSet().send(MuteRequest(.list)).notice ?? ""
        XCTAssertTrue(notice.hasPrefix("Your saved mute set couldn't be read."), notice)
        XCTAssertTrue(notice.hasSuffix(SavedMuteSet.noConsoleUser), notice)
    }
    
    /// A saved set is kept as it is whoever logs in, even one whose per-user mutes name another home folder. Only
    /// Reset makes the default set again, for the console user.
    func testASavedSetIsOnlyRewrittenByReset() throws {
        let rootDefault = MuteFile(MuteList.shippedDefault(for: ConsoleUser(name: "root", uid: 0, home: "/var/root")))
        let earlier = String(decoding: rootDefault.encoded(), as: UTF8.self)
        try writeSavedFile(earlier, in: store)
        let saved = makeSavedSet()
        let list = saved.send(MuteRequest(.list))
        XCTAssertEqual(list.mutes, rootDefault.mutes)
        XCTAssertNil(list.notice)
        XCTAssertEqual(savedFile(in: store), Data(earlier.utf8))
        
        XCTAssertEqual(saved.send(MuteRequest(.reset)).mutes, MuteFile(.shippedDefault(for: alice)).mutes)
        XCTAssertEqual(savedFile(in: store), savedBytes(.shippedDefault(for: alice)))
    }
}
