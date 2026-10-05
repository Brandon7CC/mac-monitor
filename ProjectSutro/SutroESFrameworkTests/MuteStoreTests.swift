//
//  MuteStoreTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Saved mute set file
/// Pins the saved set's file: atomic, owner-only writes, reads that never follow a link or wait on a FIFO, damaged
/// files moved aside, newer files left alone, and a directory others can write refused.
final class MuteStoreTests: XCTestCase {
    /// A small list.
    private let list = MuteList([PathMute(path: "/usr/bin/yes", type: ES_MUTE_PATH_TYPE_LITERAL),
                                 PathMute(path: "/private/tmp/", type: ES_MUTE_PATH_TYPE_TARGET_PREFIX,
                                          events: [ES_EVENT_TYPE_NOTIFY_OPEN])])
    
    /// A file's permission bits.
    ///
    /// - Parameter path: The file.
    /// - Returns: Its mode & 0777.
    private func mode(_ path: String) -> mode_t {
        var info = stat()
        lstat(path, &info)
        return info.st_mode & 0o777
    }
    
    /// No file, or no directory, is a first run.
    ///
    /// - Throws: An unexpected error.
    func testNothingSavedIsMissing() throws {
        let store = try makeMuteStore()
        XCTAssertEqual(try store.load(), .missing)
        let unborn = MuteStore(directory: store.directory.appendingPathComponent("unborn"), owner: getuid())
        XCTAssertEqual(try unborn.load(), .missing)
    }
    
    /// Saving writes the canonical file, owner-only, and nothing else; it reads back as the same list.
    ///
    /// - Throws: An unexpected error.
    func testSaveWritesTheCanonicalFile() throws {
        let store = try makeMuteStore()
        try store.save(list)
        XCTAssertEqual(savedFile(in: store), MuteFile(list).encoded())
        XCTAssertEqual(mode(store.fileURL.path), 0o600)
        XCTAssertEqual(namesInDirectory(of: store), [MuteStore.fileName])
        XCTAssertEqual(try store.load(), .saved(list, warnings: []))
    }
    
    /// Saving creates a missing directory, 0700.
    ///
    /// - Throws: An unexpected error.
    func testSaveCreatesTheDirectory() throws {
        let parent = try makeMuteDirectory()
        let store = MuteStore(directory: parent.appendingPathComponent("store"), owner: getuid())
        try store.save(list)
        XCTAssertEqual(mode(store.directory.path), 0o700)
        XCTAssertEqual(try store.load(), .saved(list, warnings: []))
    }
    
    /// A temporary file a crash left behind is removed on load.
    ///
    /// - Throws: An unexpected error.
    func testLeftoversAreRemoved() throws {
        let store = try makeMuteStore()
        try store.save(list)
        try Data("half".utf8).write(to: store.directory.appendingPathComponent(".mutes.ABC123"))
        _ = try store.load()
        XCTAssertEqual(namesInDirectory(of: store), [MuteStore.fileName])
    }
    
    /// A save that fails keeps the old file and leaves no temporary file.
    ///
    /// - Throws: An unexpected error.
    func testFailedSaveKeepsTheOldFile() throws {
        let store = try makeMuteStore()
        try store.save(list)
        chmod(store.directory.path, 0o500)
        defer { chmod(store.directory.path, 0o700) }
        XCTAssertThrowsError(try store.save(.testDefault)) { error in
            guard case .writeFailed? = error as? MuteStoreError else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(savedFile(in: store), MuteFile(list).encoded())
        XCTAssertEqual(namesInDirectory(of: store), [MuteStore.fileName])
    }
    
    /// Corrupt JSON, or a file over 1 MiB, is moved aside and reported.
    ///
    /// - Throws: An unexpected error.
    func testUnreadableFilesAreMovedAside() throws {
        let store = try makeMuteStore()
        for contents in ["nope", String(repeating: " ", count: MuteLimits.maxFileBytes + 1)] {
            try writeSavedFile(contents, in: store)
            guard case .unreadable(_, let kept) = try store.load() else { return XCTFail("read \(contents.prefix(4))") }
            XCTAssertEqual(kept, store.unreadableURL)
            XCTAssertEqual(FileManager.default.contents(atPath: store.unreadableURL.path), Data(contents.utf8))
            XCTAssertNil(savedFile(in: store))
        }
    }
    
    /// A FIFO named `mutes.json` is moved aside without being opened, so loading never waits for a writer.
    ///
    /// - Throws: An unexpected error.
    func testAFIFOIsNeverOpened() throws {
        let store = try makeMuteStore()
        XCTAssertEqual(mkfifo(store.fileURL.path, 0o600), 0)
        let started = Date()
        guard case .unreadable(let reason, _) = try store.load() else { return XCTFail("read a FIFO") }
        XCTAssertLessThan(Date().timeIntervalSince(started), 1)
        XCTAssertTrue(reason.contains("regular file"), reason)
        XCTAssertEqual(namesInDirectory(of: store), [MuteStore.unreadableFileName])
    }
    
    /// A link named `mutes.json` is moved aside itself; what it points to is never read or touched.
    ///
    /// - Throws: An unexpected error.
    func testALinkIsNeverFollowed() throws {
        let store = try makeMuteStore()
        let target = try makeMuteDirectory().appendingPathComponent("elsewhere.json")
        let contents = MuteFile(list).encoded()
        try contents.write(to: target)
        try FileManager.default.createSymbolicLink(at: store.fileURL, withDestinationURL: target)
        guard case .unreadable = try store.load() else { return XCTFail("followed a link") }
        let moved = try FileManager.default.destinationOfSymbolicLink(atPath: store.unreadableURL.path)
        XCTAssertEqual(moved, target.path)
        XCTAssertEqual(FileManager.default.contents(atPath: target.path), contents)
    }
    
    /// A file from a newer Mac Monitor is reported and left byte for byte as it was.
    ///
    /// - Throws: An unexpected error.
    func testANewerFileIsLeftAlone() throws {
        let store = try makeMuteStore()
        let newer = #"{"version": 2, "mutes": [], "rules": []}"#
        try writeSavedFile(newer, in: store)
        XCTAssertEqual(try store.load(), .newer(version: 2))
        XCTAssertEqual(savedFile(in: store), Data(newer.utf8))
    }
    
    /// Event names only a newer Mac Monitor knows are left out with a warning, not treated as damage.
    ///
    /// - Throws: An unexpected error.
    func testUnknownEventsAreLeftOut() throws {
        let store = try makeMuteStore()
        try writeSavedFile("""
            {"version": 1, "mutes": [
              {"path": "/a", "type": "ES_MUTE_PATH_TYPE_LITERAL",
               "events": ["ES_EVENT_TYPE_NOTIFY_OPEN", "ES_EVENT_TYPE_NOTIFY_FUTURE"]},
              {"path": "/b", "type": "ES_MUTE_PATH_TYPE_LITERAL", "events": ["ES_EVENT_TYPE_NOTIFY_FUTURE"]}]}
            """, in: store)
        guard case .saved(let saved, let warnings) = try store.load() else { return XCTFail("not read") }
        XCTAssertEqual(saved.mutes, [PathMute(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL,
                                              events: [ES_EVENT_TYPE_NOTIFY_OPEN])])
        XCTAssertEqual(warnings.count, 2)
    }
    
    /// A directory others can write, or one owned by someone else, is neither read nor written.
    ///
    /// - Throws: An unexpected error.
    func testAnUntrustedDirectoryIsRefused() throws {
        let store = try makeMuteStore()
        try store.save(list)
        chmod(store.directory.path, 0o777)
        defer { chmod(store.directory.path, 0o700) }
        XCTAssertThrowsError(try store.load()) { error in
            guard case .untrustedDirectory? = error as? MuteStoreError else { return XCTFail("\(error)") }
        }
        XCTAssertThrowsError(try store.save(.testDefault))
        XCTAssertEqual(savedFile(in: store), MuteFile(list).encoded())
        
        chmod(store.directory.path, 0o700)
        guard getuid() != 0 else { return }
        let rootOwned = MuteStore(directory: store.directory, owner: 0)
        XCTAssertThrowsError(try rootOwned.load()) { error in
            XCTAssertEqual(error as? MuteStoreError,
                           .untrustedDirectory("\(store.directory.path) isn't owned by root."))
        }
        XCTAssertThrowsError(try rootOwned.save(.testDefault))
        XCTAssertEqual(savedFile(in: store), MuteFile(list).encoded())
    }
}
