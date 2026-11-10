//
//  RootFileStoreTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Root-owned saved files
/// Pins what every saved set's file shares, with a layout that isn't the mute set's: atomic, owner-only writes, reads
/// that never follow a link or wait on a FIFO, the size cap both ways, damaged files moved aside, and a directory
/// that's a link, a file, or one its group or others can write refused. `MuteStoreTests` pins the same through the
/// saved mute set.
final class RootFileStoreTests: XCTestCase {
    /// A layout no saved set uses, with a small cap.
    private let layout = RootFileStore.Layout(fileName: "things.json", unreadableFileName: "things.unreadable.json",
                                              temporaryPrefix: ".things.", maxBytes: 4 << 10, noun: "saved thing set")
    /// Some bytes to save.
    private let contents = Data(#"{"version":1}"#.utf8)

    /// A store in a fresh 0700 directory owned by the user running the test, as root owns the real one.
    ///
    /// - Returns: The store.
    /// - Throws: If its directory can't be created.
    private func makeStore() throws -> RootFileStore {
        RootFileStore(directory: try makeTemporaryDirectory(prefix: "RootFileStoreTests", mode: 0o700),
                      owner: getuid(), layout: layout)
    }

    /// - Parameter path: A file or directory.
    /// - Returns: Its mode & 0777.
    private func mode(_ path: String) -> mode_t {
        var info = stat()
        lstat(path, &info)
        return info.st_mode & 0o777
    }

    /// - Parameter store: The store.
    /// - Returns: The names in its directory, sorted.
    private func names(in store: RootFileStore) -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: store.directory.path)) ?? []).sorted()
    }

    /// - Parameter store: The store.
    /// - Returns: The saved file's bytes, bypassing the store, or `nil` if there's none.
    private func savedFile(in store: RootFileStore) -> Data? {
        FileManager.default.contents(atPath: store.fileURL.path)
    }

    /// No file, or no directory, reads as missing.
    func testNothingSavedIsMissing() throws {
        let store = try makeStore()
        XCTAssertEqual(try store.read(), .missing)
        let unborn = RootFileStore(directory: store.directory.appendingPathComponent("unborn"), owner: getuid(),
                                   layout: layout)
        XCTAssertEqual(try unborn.read(), .missing)
    }

    /// A write leaves only the file, owner-only, and reads back byte for byte.
    func testWriteIsOwnerOnlyAndReadsBack() throws {
        let store = try makeStore()
        try store.write(contents)
        XCTAssertEqual(mode(store.fileURL.path), 0o600)
        XCTAssertEqual(names(in: store), [layout.fileName])
        XCTAssertEqual(try store.read(), .read(contents))
    }

    /// A write creates a missing directory, 0700.
    func testWriteCreatesTheDirectory() throws {
        let parent = try makeTemporaryDirectory(mode: 0o700)
        let store = RootFileStore(directory: parent.appendingPathComponent("store"), owner: getuid(), layout: layout)
        try store.write(contents)
        XCTAssertEqual(mode(store.directory.path), 0o700)
        XCTAssertEqual(try store.read(), .read(contents))
    }

    /// Temporary files a crash left behind, by this layout's prefix only, are removed on read.
    func testLeftoversAreRemoved() throws {
        let store = try makeStore()
        try store.write(contents)
        try Data("half".utf8).write(to: store.directory.appendingPathComponent(".things.ABC123"))
        try Data("other".utf8).write(to: store.directory.appendingPathComponent(".mutes.ABC123"))
        _ = try store.read()
        XCTAssertEqual(names(in: store), [".mutes.ABC123", layout.fileName])
    }

    /// A write that fails keeps the old file and leaves no temporary file.
    func testFailedWriteKeepsTheOldFile() throws {
        let store = try makeStore()
        try store.write(contents)
        chmod(store.directory.path, 0o500)
        XCTAssertThrowsError(try store.write(Data("new".utf8))) { error in
            guard case .writeFailed? = error as? RootFileStoreError else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(savedFile(in: store), contents)
        XCTAssertEqual(names(in: store), [layout.fileName])
    }

    /// A write over the cap is refused, naming the file and the cap, and the old file is kept.
    func testAWriteOverTheCapIsRefused() throws {
        let store = try makeStore()
        try store.write(contents)
        XCTAssertNoThrow(try store.write(Data(count: layout.maxBytes)))
        try store.write(contents)
        XCTAssertEqual(thrown(RootFileStoreError.self) { try store.write(Data(count: layout.maxBytes + 1)) },
                       .writeFailed("The saved thing set would be larger than 4 KiB."))
        XCTAssertEqual(savedFile(in: store), contents)
        XCTAssertEqual(names(in: store), [layout.fileName])
    }

    /// A file over the cap is reported with its size, without being read, and left where it is.
    func testAFileOverTheCapIsTooLarge() throws {
        let store = try makeStore()
        try Data(count: layout.maxBytes + 1).write(to: store.fileURL)
        XCTAssertEqual(try store.read(), .tooLarge(bytes: layout.maxBytes + 1))
        XCTAssertEqual(names(in: store), [layout.fileName])
    }

    /// A FIFO is reported without being opened, so reading never waits for a writer.
    func testAFIFOIsNeverOpened() throws {
        let store = try makeStore()
        XCTAssertEqual(mkfifo(store.fileURL.path, 0o600), 0)
        let started = Date()
        guard case .unreadable(let reason) = try store.read() else { return XCTFail("read a FIFO") }
        XCTAssertLessThan(Date().timeIntervalSince(started), 1)
        XCTAssertTrue(reason.contains("regular file"), reason)
    }

    /// A link is reported, and moved aside itself. What it points to is never read or touched.
    func testALinkIsNeverFollowed() throws {
        let store = try makeStore()
        let target = try makeTemporaryDirectory().appendingPathComponent("elsewhere.json")
        try contents.write(to: target)
        try FileManager.default.createSymbolicLink(at: store.fileURL, withDestinationURL: target)
        guard case .unreadable = try store.read() else { return XCTFail("followed a link") }
        XCTAssertEqual(store.moveAside(), store.unreadableURL)
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: store.unreadableURL.path), target.path)
        XCTAssertEqual(FileManager.default.contents(atPath: target.path), contents)
    }

    /// Moving aside replaces an older unreadable file, and there's nothing to move once it's gone.
    func testMoveAsideReplacesAnOlderOne() throws {
        let store = try makeStore()
        try Data("old".utf8).write(to: store.unreadableURL)
        try store.write(contents)
        XCTAssertEqual(store.moveAside(), store.unreadableURL)
        XCTAssertEqual(FileManager.default.contents(atPath: store.unreadableURL.path), contents)
        XCTAssertEqual(names(in: store), [layout.unreadableFileName])
        XCTAssertNil(store.moveAside())
    }

    /// A directory others can write, or one owned by someone else, is neither read nor written.
    func testAnUntrustedDirectoryIsRefused() throws {
        let store = try makeStore()
        try store.write(contents)
        chmod(store.directory.path, 0o777)
        XCTAssertEqual(thrown(RootFileStoreError.self) { try store.read() },
                       .untrustedDirectory("Others can write to \(store.directory.path)."))
        XCTAssertThrowsError(try store.write(Data("new".utf8)))
        XCTAssertEqual(savedFile(in: store), contents)

        chmod(store.directory.path, 0o700)
        guard getuid() != 0 else { return }
        let rootOwned = RootFileStore(directory: store.directory, owner: 0, layout: layout)
        XCTAssertEqual(thrown(RootFileStoreError.self) { try rootOwned.read() },
                       .untrustedDirectory("\(store.directory.path) isn't owned by root."))
        XCTAssertThrowsError(try rootOwned.write(Data("new".utf8)))
        XCTAssertEqual(savedFile(in: store), contents)
    }

    /// Only the directory itself is trusted, and only when no one but its owner can write it: a link to a trusted
    /// directory, a directory its group can write, and a file in the directory's place are each neither read nor
    /// written through, and nothing is created in their place. A directory others can only read is trusted.
    func testOnlyARealDirectoryOnlyItsOwnerCanWriteIsTrusted() throws {
        let trusted = try makeStore()
        try trusted.write(contents)
        let parent = try makeTemporaryDirectory(prefix: "RootFileStoreTests", mode: 0o700)

        let link = parent.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: trusted.directory)
        let linked = RootFileStore(directory: link, owner: getuid(), layout: layout)
        XCTAssertEqual(thrown(RootFileStoreError.self) { try linked.read() },
                       .untrustedDirectory("\(link.path) isn't a directory."))
        XCTAssertEqual(thrown(RootFileStoreError.self) { try linked.write(Data("new".utf8)) },
                       .untrustedDirectory("\(link.path) isn't a directory."))
        XCTAssertEqual(savedFile(in: trusted), contents, "Nothing was written through the link.")

        let file = parent.appendingPathComponent("file")
        try contents.write(to: file)
        let misplaced = RootFileStore(directory: file, owner: getuid(), layout: layout)
        XCTAssertEqual(thrown(RootFileStoreError.self) { try misplaced.read() },
                       .untrustedDirectory("\(file.path) isn't a directory."))
        XCTAssertEqual(thrown(RootFileStoreError.self) { try misplaced.write(Data("new".utf8)) },
                       .untrustedDirectory("\(file.path) isn't a directory."))
        XCTAssertEqual(FileManager.default.contents(atPath: file.path), contents)

        for writable: mode_t in [0o770, 0o720, 0o702, 0o722] {
            chmod(trusted.directory.path, writable)
            XCTAssertEqual(thrown(RootFileStoreError.self) { try trusted.read() },
                           .untrustedDirectory("Others can write to \(trusted.directory.path)."),
                           String(writable, radix: 8))
            XCTAssertNotNil(thrown(RootFileStoreError.self) { try trusted.write(Data("new".utf8)) })
        }
        XCTAssertEqual(savedFile(in: trusted), contents)

        chmod(trusted.directory.path, 0o755)
        XCTAssertEqual(try trusted.read(), .read(contents))
        XCTAssertNoThrow(try trusted.write(Data("new".utf8)))
    }

    /// The cap reads in the largest whole unit, and the mute store keeps its own names and 1 MiB cap.
    func testTheCapInWordsAndTheMuteLayout() {
        let sizes = [1 << 20: "1 MiB", 4 << 20: "4 MiB", 64 << 10: "64 KiB", 1000: "1000 bytes", 0: "0 bytes"]
        for (bytes, text) in sizes {
            let store = RootFileStore(owner: getuid(), layout: RootFileStore.Layout(
                fileName: "a", unreadableFileName: "b", temporaryPrefix: ".a.", maxBytes: bytes, noun: "set"))
            XCTAssertEqual(store.maxSizeText, text)
        }
        XCTAssertEqual(MuteStore.layout, RootFileStore.Layout(
            fileName: "mutes.json", unreadableFileName: "mutes.unreadable.json", temporaryPrefix: ".mutes.",
            maxBytes: MuteLimits.maxFileBytes, noun: "saved mute set"))
        XCTAssertEqual(MuteStore.systemDirectory.path,
                       "/Library/Application Support/com.swiftlydetecting.agent.securityextension")
    }
}
