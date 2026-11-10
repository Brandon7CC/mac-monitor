//
//  ScriptReadingTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Reading a script
/// Pins how the Security Extension reads the script an exec runs: only a file the exec's user could read, only the
/// file ES saw, and as much of its text as there is.
final class ScriptReadingTests: XCTestCase {
    /// A user and group that aren't the test's.
    private let stranger = FileReader(uid: 12345, gid: 12345)
    /// The test's own user and group.
    private let me = FileReader(uid: getuid(), gid: getgid())

    /// Write bytes to a new file in a temporary directory.
    ///
    /// - Parameters:
    ///   - bytes: The file's contents.
    ///   - name: The file's name.
    ///   - mode: The file's permissions.
    /// - Returns: The file's path.
    private func file(_ bytes: Data, named name: String = "tool.sh", mode: mode_t = 0o644) throws -> String {
        let path = try makeTemporaryDirectory().appendingPathComponent(name).path
        try bytes.write(to: URL(fileURLWithPath: path))
        XCTAssertEqual(chmod(path, mode), 0)
        return path
    }

    /// A `stat` of a regular file.
    ///
    /// - Parameters:
    ///   - mode: Its permissions.
    ///   - uid: Its owner.
    ///   - gid: Its group.
    /// - Returns: The `stat`.
    private func info(_ mode: mode_t, uid: uid_t = 501, gid: gid_t = 20) -> stat {
        var info = stat()
        (info.st_mode, info.st_uid, info.st_gid) = (S_IFREG | mode, uid, gid)
        return info
    }

    /// Add an entry to a path's ACL, as `chmod +a` does.
    ///
    /// - Parameters:
    ///   - entry: The entry, such as `"nobody deny read"`.
    ///   - path: The file or directory.
    private func addACLEntry(_ entry: String, to path: String) throws {
        let chmod = Process()
        chmod.executableURL = URL(fileURLWithPath: "/bin/chmod")
        chmod.arguments = ["+a", entry, path]
        try chmod.run()
        chmod.waitUntilExit()
        XCTAssertEqual(chmod.terminationStatus, 0, "chmod +a \"\(entry)\"")
    }

    // MARK: Who the file is read for
    /// Only one class's bit counts, as the kernel picks it: the owner's, else the group's, else everyone's. Root
    /// reads anything.
    func testReadPermissionClass() {
        let owner = FileReader(uid: 501, gid: 20), member = FileReader(uid: 502, gid: 20)
        let other = FileReader(uid: 503, gid: 30), root = FileReader(uid: 0, gid: 0)
        XCTAssertTrue(owner.canRead(info(0o400)))
        XCTAssertFalse(owner.canRead(info(0o044)), "an owner without the owner bit can't read it")
        XCTAssertTrue(member.canRead(info(0o040)))
        XCTAssertFalse(member.canRead(info(0o404)), "a group member without the group bit can't read it")
        XCTAssertTrue(other.canRead(info(0o044)))
        XCTAssertFalse(other.canRead(info(0o440)))
        XCTAssertTrue(root.canRead(info(0o000)))
        XCTAssertTrue(FileReader(token: AuditToken(pid: 1, pidversion: 1, asid: 1, auid: 501, euid: 0, ruid: 501,
                                                   rgid: 20, egid: 0)).canRead(info(0o000)))
    }

    /// A reader whose own group isn't the file's may still be in it through a supplementary group (every local user
    /// is in `everyone`, most console users in `admin`), and the kernel then uses the group's bit alone. So a file
    /// whose group bit denies them is refused, even when everyone's bit allows it.
    func testASupplementaryGroupCantLetAFileThrough() {
        let console = FileReader(uid: 501, gid: 20)
        XCTAssertFalse(console.canRead(info(0o604, uid: 0, gid: 80)), "root:admin 0604 is denied to an admin")
        XCTAssertFalse(console.canRead(info(0o604, uid: 0, gid: 12)), "root:everyone 0604 is denied to everyone")
        XCTAssertFalse(console.canRead(info(0o640, uid: 0, gid: 80)), "it may not be in admin")
        XCTAssertTrue(console.canRead(info(0o644, uid: 0, gid: 80)), "either class may read it")
        XCTAssertTrue(console.canRead(info(0o640, uid: 0, gid: 20)), "the file's group is the reader's own")
        XCTAssertFalse(console.canRead(info(0o604, uid: 0, gid: 20)), "the file's group is the reader's own")
    }

    /// A directory is searched with its execute bit, and only a directory is searched.
    func testSearchPermission() {
        var directory = info(0o701)
        directory.st_mode = S_IFDIR | 0o701
        XCTAssertTrue(FileReader(uid: 501, gid: 20).canSearch(directory))
        XCTAssertFalse(FileReader(uid: 502, gid: 20).canSearch(directory))
        XCTAssertFalse(FileReader(uid: 503, gid: 30).canSearch(directory), "it may be in the directory's group")
        directory.st_mode = S_IFDIR | 0o711
        XCTAssertTrue(FileReader(uid: 503, gid: 30).canSearch(directory))
        XCTAssertFalse(FileReader(uid: 501, gid: 20).canSearch(info(0o700)), "a file isn't a directory")
    }

    /// An ACL entry denying anyone reading a file refuses it: whom the entry names isn't looked up. An entry that
    /// allows reading, or denies something else, doesn't refuse it.
    func testAnACLDenyingReadRefusesTheFile() throws {
        let denied = try file(Data("echo hi\n".utf8))
        XCTAssertFalse(AccessControlList.denies(ACL_READ_DATA, at: denied), "no ACL")
        try addACLEntry("nobody deny read", to: denied)
        XCTAssertTrue(AccessControlList.denies(ACL_READ_DATA, at: denied))
        XCTAssertNil(ProcessHelpers.getScriptContents(at: denied, for: me))
        XCTAssertEqual(ProcessHelpers.getScriptContents(at: denied, for: nil), "echo hi\n", "Mac Monitor itself")

        let allowed = try file(Data("echo hi\n".utf8))
        try addACLEntry("nobody allow read", to: allowed)
        try addACLEntry("nobody deny write", to: allowed)
        XCTAssertFalse(AccessControlList.denies(ACL_READ_DATA, at: allowed))
        XCTAssertEqual(ProcessHelpers.getScriptContents(at: allowed, for: me), "echo hi\n")
    }

    /// An ACL entry denying anyone searching a directory refuses every file inside it.
    func testAnACLDenyingSearchRefusesWhatsInside() throws {
        let path = try file(Data("echo hi\n".utf8))
        XCTAssertNotNil(ProcessHelpers.getScriptContents(at: path, for: me))
        try addACLEntry("nobody deny search", to: path.deletingLastPathComponent)
        XCTAssertNil(ProcessHelpers.getScriptContents(at: path, for: me))
        XCTAssertNotNil(ProcessHelpers.getScriptContents(at: path, for: nil), "Mac Monitor itself")
    }

    /// `python3 -c 1 /etc/sudoers` read all of a file the user couldn't. A file only its owner can read gives a reader
    /// who isn't its owner no content and no script, and a reader who is, or none, both.
    func testAFileTheReaderCantReadIsntRead() throws {
        let path = try file(Data("secret\n".utf8), named: "private.txt", mode: 0o600)
        let python = try XCTUnwrap(ScriptInterpreter.named("python3"))
        let directory = path.deletingLastPathComponent

        XCTAssertNil(ProcessHelpers.getScriptContents(at: path, for: stranger))
        XCTAssertNil(ProcessHelpers.scriptFromArgs(args: ["python3", "private.txt"], interpreter: python,
                                                   workingDirectory: directory, reader: stranger))
        XCTAssertEqual(ProcessHelpers.getScriptContents(at: path, for: nil), "secret\n")
        XCTAssertEqual(ProcessHelpers.getScriptContents(at: path, for: me), "secret\n")
        let found = ProcessHelpers.scriptFromArgs(args: ["python3", "private.txt"], interpreter: python,
                                                  workingDirectory: directory, reader: me)
        XCTAssertEqual(found?.path, path)
        XCTAssertEqual(found?.content, "secret\n")
    }

    /// A file everyone may read inside a folder the reader can't search is out of their reach, as is
    /// `/etc/sudoers`, while `/etc/hosts` isn't.
    func testAFileOutOfReachIsntRead() throws {
        let path = try file(Data("echo hi\n".utf8), mode: 0o644)
        XCTAssertNil(ProcessHelpers.getScriptContents(at: path, for: stranger), "the temporary folder is the test's")
        XCTAssertNotNil(ProcessHelpers.getScriptContents(at: path, for: me))
        XCTAssertNotNil(ProcessHelpers.readRegularFile(at: "/etc/hosts", for: stranger))
        XCTAssertNil(ProcessHelpers.readRegularFile(at: "/etc/sudoers", for: stranger))
    }

    // MARK: Which file is read
    /// Only the file ES saw is read: one swapped in under its path, or changed in size, isn't.
    func testOnlyTheReportedFileIsRead() throws {
        let path = try file(Data("echo real\n".utf8))
        var info = stat()
        XCTAssertEqual(stat(path, &info), 0)
        let reported = FileIdentity(info)
        XCTAssertEqual(ProcessHelpers.getScriptContents(at: path, for: me, expecting: reported), "echo real\n")

        var elsewhere = info
        elsewhere.st_dev += 1
        XCTAssertNil(ProcessHelpers.getScriptContents(at: path, for: me, expecting: FileIdentity(elsewhere)),
                     "another device")

        let decoy = path.deletingLastPathComponent.appendingPathComponent("decoy.sh")
        try Data("echo decoy\n".utf8).write(to: URL(fileURLWithPath: decoy))
        XCTAssertEqual(rename(decoy, path), 0)
        XCTAssertNil(ProcessHelpers.getScriptContents(at: path, for: me, expecting: reported), "another inode")
        XCTAssertEqual(ProcessHelpers.getScriptContents(at: path, for: me), "echo decoy\n")

        XCTAssertEqual(stat(path, &info), 0)
        let swapped = FileIdentity(info)
        let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
        try handle.seekToEnd()
        try handle.write(contentsOf: Data("echo more\n".utf8))
        try handle.close()
        XCTAssertNil(ProcessHelpers.getScriptContents(at: path, for: me, expecting: swapped), "another size")
    }

    /// The identity an event carries matches the file's own.
    func testReportedIdentityMatchesTheFile() throws {
        let path = try file(Data("echo hi\n".utf8))
        var info = stat()
        XCTAssertEqual(stat(path, &info), 0)
        XCTAssertTrue(FileIdentity(Stat(from: info)).matches(info))
        XCTAssertEqual(FileIdentity(Stat(from: info)), FileIdentity(info))
    }

    // MARK: Telling a script from a binary
    /// Text before the first NUL makes a script, whatever bytes that aren't UTF-8 it holds or follow it. A Mach-O or
    /// universal binary, or bytes with nothing printable before their first NUL, don't.
    func testTellingAScriptFromABinary() {
        let scripts: [Data] = [
            Data("echo hi\n".utf8), Data("\n".utf8),
            /// A multibyte character the probe cuts.
            Data((String(repeating: "a", count: 511) + "\u{E9}").utf8).prefix(512),
            Data(repeating: 0x61, count: 511) + Data([0xFF]), Data("# caf".utf8) + Data([0xFF]) + Data("\necho\n".utf8),
            Data("#!/bin/sh\n".utf8) + Data([0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00]),
        ]
        for data in scripts {
            XCTAssertTrue(ProcessHelpers.isScriptProbe(data), "\(Array(data.prefix(16)))")
        }
        let binaries: [Data] = [
            Data(), Data([0xC3]), Data([0x00]) + Data("echo hi\n".utf8), Data([0xFF, 0xFE, 0x01, 0x00, 0x61]),
            Data([0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01]),
            Data([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02]),
            Data([0xCF, 0xFA, 0xED, 0xFE]) + Data("echo hi\n".utf8), Data([0xFE, 0xED, 0xFA, 0xCE]) + Data("echo".utf8),
            Data([0x1F, 0x8B, 0x08, 0x00]),
        ]
        for data in binaries {
            XCTAssertFalse(ProcessHelpers.isScriptProbe(data), "\(Array(data.prefix(16)))")
        }
    }

    /// The probe and the text come from one open file: one renamed over its path after the open isn't read.
    func testTheProbedFileIsTheOneRead() throws {
        let script = "#!/bin/bash\n" + String(repeating: "echo hi\n", count: 200)
        let path = try file(Data(script.utf8))
        let opened = try XCTUnwrap(ProcessHelpers.openRegularFile(at: path, for: me))
        let decoy = path.deletingLastPathComponent.appendingPathComponent("decoy.sh")
        try Data("echo decoy\n".utf8).write(to: URL(fileURLWithPath: decoy))
        XCTAssertEqual(rename(decoy, path), 0)
        XCTAssertEqual(ProcessHelpers.scriptText(readingFrom: opened), script, "past the probe, from the same file")
        XCTAssertEqual(ProcessHelpers.getScriptContents(at: path, for: me), "echo decoy\n")
    }

    /// The text read from an open file stops at its first NUL, inside the probe or past it, and a binary has none.
    func testScriptTextFromAnOpenFile() throws {
        let header = "#!/bin/sh\nexit 0\n"
        let short = try XCTUnwrap(ProcessHelpers.openRegularFile(at: try file(Data(header.utf8) + Data([0, 0x61]))))
        XCTAssertEqual(ProcessHelpers.scriptText(readingFrom: short), header)
        let long = String(repeating: "a", count: 700)
        let past = try XCTUnwrap(ProcessHelpers.openRegularFile(at: try file(Data(long.utf8) + Data([0, 0x61]))))
        XCTAssertEqual(ProcessHelpers.scriptText(readingFrom: past), long)
        let machO = try file(Data([0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01]))
        XCTAssertNil(ProcessHelpers.scriptText(readingFrom: try XCTUnwrap(ProcessHelpers.openRegularFile(at: machO))))
        let empty = try XCTUnwrap(ProcessHelpers.openRegularFile(at: try file(Data())))
        XCTAssertNil(ProcessHelpers.scriptText(readingFrom: empty))
    }

    // MARK: A script's text
    /// One byte that isn't UTF-8 reads as U+FFFD, rather than losing the script. A plist stays strict.
    func testAnInvalidByteKeepsTheScript() throws {
        let path = try file(Data("echo hi\n".utf8) + Data([0xFF]) + Data("echo bye\n".utf8))
        XCTAssertEqual(ProcessHelpers.getScriptContents(at: path, for: me), "echo hi\n\u{FFFD}echo bye\n")
        XCTAssertNil(ProcessHelpers.getFileContents(at: path))
    }

    /// A self-extracting script keeps its shell header: the text stops at the payload's first NUL.
    func testAnAppendedPayloadKeepsTheHeader() throws {
        let header = "#!/bin/sh\necho extracting\ntail -c +4 \"$0\" | tar xz\nexit 0\n"
        let gzip = try file(Data(header.utf8) + Data([0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]))
        XCTAssertEqual(ProcessHelpers.getScriptContents(at: gzip, for: me), header + "\u{1F}\u{FFFD}\u{08}")

        let machO = try file(Data(header.utf8) + Data([0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01, 0xFF]))
        let text = try XCTUnwrap(ProcessHelpers.getScriptContents(at: machO, for: me))
        XCTAssertTrue(text.hasPrefix(header))
        XCTAssertFalse(text.contains("\0"))
        XCTAssertNil(ProcessHelpers.getFileContents(at: machO))
    }

    /// A script's text stops at the limit, back to the end of a whole character, and at its first NUL before that.
    func testScriptTextStopsAtTheLimit() {
        let limit = ProcessHelpers.fileContentsLimit
        let exact = Data(repeating: 0x61, count: limit)
        XCTAssertEqual(ProcessHelpers.scriptText(of: exact), String(repeating: "a", count: limit))
        /// "é" is two bytes, the first of them the limit's last.
        let long = Data(repeating: 0x61, count: limit - 1) + Data("\u{E9}tail".utf8)
        XCTAssertEqual(ProcessHelpers.scriptText(of: long), String(repeating: "a", count: limit - 1))
        XCTAssertEqual(ProcessHelpers.scriptText(of: Data([0x61, 0x00, 0x62])), "a")
        XCTAssertEqual(ProcessHelpers.scriptText(of: Data()), "")
        XCTAssertEqual(ProcessHelpers.scriptText(of: Data("echo hi\n".utf8).dropFirst(5)), "hi\n", "a slice")
    }

    // MARK: Line count
    /// Lines are counted by newline byte: a final newline doesn't start another, and `\r\n` ends one.
    func testLineCount() {
        XCTAssertEqual("".lineCount, 1)
        XCTAssertEqual("one".lineCount, 1)
        XCTAssertEqual("one\n".lineCount, 1)
        XCTAssertEqual("one\ntwo".lineCount, 2)
        XCTAssertEqual("one\r\ntwo\r\n".lineCount, 2)
        XCTAssertEqual("\n\n".lineCount, 2)
        XCTAssertEqual("caf\u{E9}\n\u{1F600}\n".lineCount, 2)
    }
}
