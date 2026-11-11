//
//  ArchiveWrittenIndicatorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import UniformTypeIdentifiers
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Archive written
/// Pins Archive written on files macOS 27's own archive tools write: each is read as a capture lane reads a modified
/// close's file (``FileTypeReader``), and the type it's named by is set on a close derived from one `macmonitor
/// stream` recorded. The Security Extension's compiled set and Mac Monitor's own matching agree on every one and
/// leave none undetermined, a match is stamped as a shipped low indicator, and the rule is looked up by the file's
/// type alone, so no other close is evaluated against it.
///
/// What a file's first 4 KB and last 512 bytes name: zip (`zip`, `ditto`), tar, gzip, bzip2, xz, 7-Zip, xar
/// (`xar`, `pkgbuild`), Apple Archive, every compressed or read-only UDIF image `hdiutil` makes, a read/write image
/// (`UDRW`, raw, with no UDIF trailer) and a sparse image (`DiskImageWrittenTests` has the rest of the images). What
/// they don't: cpio, raw LZFSE, LZ4, zstd and LZMA streams. A static library is `public.archive`, and Office Open
/// XML, OpenDocument and EPUB files are documents, which the indicator leaves out.
final class ArchiveWrittenIndicatorTests: XCTestCase {
    /// A file a tool writes, and what its content should be named.
    private struct Written {
        /// What the case is.
        let label: String
        /// The tool's path.
        let tool: String
        /// Its arguments, given the folder holding `notes.txt` and the file to write.
        let arguments: (_ folder: String, _ output: String) -> [String]
        /// The type its content should be named by, or `nil` when it shouldn't be read as any.
        let type: String?
        /// Should Archive written match its write?
        let matches: Bool
    }

    /// The archives and streams the tools write, and the types the reader names them by.
    private static let written: [Written] = [
        Written(label: "zip", tool: "/usr/bin/zip", arguments: { ["-q", "-j", $1, $0 + "/notes.txt"] },
                type: "public.zip-archive", matches: true),
        Written(label: "ditto -c -k", tool: "/usr/bin/ditto", arguments: { ["-c", "-k", $0, $1] },
                type: "public.zip-archive", matches: true),
        Written(label: "tar", tool: "/usr/bin/tar", arguments: { ["-cf", $1, "-C", $0, "notes.txt"] },
                type: "public.tar-archive", matches: true),
        Written(label: "tar -z", tool: "/usr/bin/tar", arguments: { ["-czf", $1, "-C", $0, "notes.txt"] },
                type: "org.gnu.gnu-zip-archive", matches: true),
        Written(label: "tar -j", tool: "/usr/bin/tar", arguments: { ["-cjf", $1, "-C", $0, "notes.txt"] },
                type: "public.bzip2-archive", matches: true),
        Written(label: "tar -J", tool: "/usr/bin/tar", arguments: { ["-cJf", $1, "-C", $0, "notes.txt"] },
                type: "org.tukaani.xz-archive", matches: true),
        Written(label: "tar 7zip", tool: "/usr/bin/tar", arguments: { ["--format", "7zip", "-cf", $1, "-C", $0, "."] },
                type: "org.7-zip.7-zip-archive", matches: true),
        Written(label: "xar", tool: "/usr/bin/xar", arguments: { ["-cf", $1, "-C", $0, "notes.txt"] },
                type: "com.apple.xar-archive", matches: true),
        Written(label: "pkgbuild", tool: "/usr/bin/pkgbuild",
                arguments: { ["--root", $0, "--identifier", "com.example.notes", "--install-location",
                              "/tmp/notes", $1] },
                type: "com.apple.xar-archive", matches: true),
        Written(label: "aa archive", tool: "/usr/bin/aa", arguments: { ["archive", "-d", $0, "-o", $1] },
                type: "com.apple.archive", matches: true),
        Written(label: "tar cpio", tool: "/usr/bin/tar", arguments: { ["--format", "cpio", "-cf", $1, "-C", $0, "."] },
                type: "public.data", matches: false),
        Written(label: "tar newc", tool: "/usr/bin/tar", arguments: { ["--format", "newc", "-cf", $1, "-C", $0, "."] },
                type: "public.data", matches: false),
        Written(label: "tar --zstd", tool: "/usr/bin/tar", arguments: { ["--zstd", "-cf", $1, "-C", $0, "."] },
                type: "public.data", matches: false),
        Written(label: "tar --lzma", tool: "/usr/bin/tar", arguments: { ["--lzma", "-cf", $1, "-C", $0, "."] },
                type: "public.data", matches: false),
        Written(label: "tar --lz4", tool: "/usr/bin/tar", arguments: { ["--lz4", "-cf", $1, "-C", $0, "."] },
                type: "public.data", matches: false),
        Written(label: "compression_tool lzfse", tool: "/usr/bin/compression_tool",
                arguments: { ["-encode", "-a", "lzfse", "-i", $0 + "/notes.txt", "-o", $1] },
                type: "public.data", matches: false),
        Written(label: "ar", tool: "/usr/bin/ar", arguments: { ["-rcS", $1, $0 + "/notes.txt"] },
                type: "public.archive", matches: false),
    ]

    /// The disk image formats `hdiutil convert` writes, and the type their content is named by: every compressed or
    /// read-only one has a `koly` trailer, which makes it a UDIF image, and a sparse one starts with `sprs`.
    private static let images: [(format: String, type: String)] = [
        ("UDZO", "com.apple.disk-image-udif"), ("ULFO", "com.apple.disk-image-udif"),
        ("UDBZ", "com.apple.disk-image-udif"), ("ULMO", "com.apple.disk-image-udif"),
        ("UDRO", "com.apple.disk-image-udif"), ("UDSP", "com.apple.disk-image-sparse"),
    ]

    /// Each archive or stream a tool writes is named by its content, and Archive written matches exactly the archives,
    /// in the extension and in the app alike, with every indicator decided.
    func testToolsArchivesAreIdentified() throws {
        let id = try shippedID("Archive written")
        let folder = try resolvedTemporaryDirectory()
        try Data("Mac Monitor\n".utf8).write(to: URL(fileURLWithPath: folder + "/notes.txt"))
        let output = try resolvedTemporaryDirectory()
        for (index, written) in Self.written.enumerated() {
            let path = output + "/written-\(index).out"
            try runTool(written.tool, written.arguments(folder, path))
            try assertContentWrite(of: path, isNamed: written.type, matching: written.matches, id: id, written.label)
        }
    }

    /// Each image `hdiutil` makes is named by its content, from its end for a UDIF image, and Archive written matches
    /// each: a read/write image made with an HFS+ volume, a raw one, then each format converted from it.
    func testDiskImagesAreIdentified() throws {
        let id = try shippedID("Archive written")
        let output = try resolvedTemporaryDirectory()
        let blank = output + "/blank.dmg"
        let status = try runTool("/usr/bin/hdiutil", ["create", "-quiet", "-size", "1m", "-layout", "NONE", "-fs",
                                                      "HFS+", "-volname", "Notes", blank], checking: false)
        try XCTSkipUnless(status == 0, "hdiutil can't make disk images here")
        try assertContentWrite(of: blank, isNamed: "com.apple.disk-image-raw", matching: true, id: id, "UDRW")
        for image in Self.images {
            let path = output + "/image-\(image.format).dmg"
            try runTool("/usr/bin/hdiutil", ["convert", "-quiet", blank, "-format", image.format, "-o", path])
            /// A sparse image is named for its format, whatever it was asked for.
            let made = FileManager.default.fileExists(atPath: path) ? path : path + ".sparseimage"
            try assertContentWrite(of: made, isNamed: image.type, matching: true, id: id, image.format)
        }
    }

    /// A file's name doesn't matter: a zip named `.txt` is an archive, and text named `.zip` isn't.
    func testNamesDontMatter() throws {
        let id = try shippedID("Archive written")
        let folder = try resolvedTemporaryDirectory()
        try Data("Mac Monitor\n".utf8).write(to: URL(fileURLWithPath: folder + "/notes.txt"))
        let disguised = try resolvedTemporaryDirectory() + "/notes.txt"
        try runTool("/usr/bin/ditto", ["-c", "-k", folder, disguised])
        try assertContentWrite(of: disguised, isNamed: "public.zip-archive", matching: true, id: id, "a zip named .txt")
        let named = try temporaryFile(bytes: Array("PK is not a zip\n".utf8), named: "notes.zip")
        try assertContentWrite(of: named, isNamed: "public.plain-text", matching: false, id: id, "text named .zip")
    }

    /// An Office Open XML and an OpenDocument file are zips that aren't archives: `textutil` writes each, and they
    /// don't match, where a zip holding the same document does.
    func testDocumentsArentArchives() throws {
        let id = try shippedID("Archive written")
        let folder = try resolvedTemporaryDirectory()
        let notes = folder + "/notes.txt"
        try Data("Mac Monitor\n".utf8).write(to: URL(fileURLWithPath: notes))
        for (format, type) in [("docx", "org.openxmlformats.openxml"), ("odt", "org.oasis-open.opendocument")] {
            let document = folder + "/notes." + format
            try runTool("/usr/bin/textutil", ["-convert", format, notes, "-output", document])
            try assertContentWrite(of: document, isNamed: type, matching: false, id: id, format)
            let zipped = folder + "/" + format + ".zip"
            try runTool("/usr/bin/zip", ["-q", "-j", zipped, document])
            try assertContentWrite(of: zipped, isNamed: "public.zip-archive", matching: true, id: id,
                                   "zipped " + format)
        }
    }

    /// zip(1) writes to a temporary `ziXXXXXX` and renames it to the archive's name at once, so the modified close
    /// names a path that's gone by the read: the archive is found where it is now, and still matches.
    func testArchiveRenamedAtOnceMatches() throws {
        let id = try shippedID("Archive written")
        let folder = try resolvedTemporaryDirectory()
        try Data("Mac Monitor\n".utf8).write(to: URL(fileURLWithPath: folder + "/notes.txt"))
        /// zip(1) names its output `.zip` when the name has no extension: the temporary name here is `zi*.zip`.
        let temporary = folder + "/ziAbc123.zip"
        try runTool("/usr/bin/zip", ["-q", "-j", temporary, folder + "/notes.txt"])
        let closed = try fileStat(temporary)
        XCTAssertEqual(rename(temporary, folder + "/loot.zip"), 0)
        try assertContentWrite(of: temporary, stat: closed, isNamed: "public.zip-archive", matching: true, id: id,
                               "renamed at once")
    }

    /// An unmodified close of an archive isn't a write, nor is Time Machine's copy of one, but a process that only
    /// calls itself backupd is.
    func testUnmodifiedClosesAndBackupsDontMatch() throws {
        let id = try shippedID("Archive written")
        let zip = "public.zip-archive"
        let cases: [(String, Message, Bool)] = [
            ("a modified close", try derivedClose(at: "/Users/marcus/loot", type: zip), true),
            ("an unmodified close", try derivedClose(at: "/Users/marcus/loot", type: zip, modified: false), false),
            ("Time Machine", try derivedClose(at: "/Volumes/Backups/loot", type: zip, by: (Indicator.backupd, true)),
             false),
            ("another backupd", try derivedClose(at: "/Users/marcus/loot", type: zip, by: (Indicator.backupd, false)),
             true),
            ("no type", try derivedClose(at: "/Users/marcus/loot.zip", type: nil), false),
        ]
        for (label, message, matches) in cases {
            try assertShippedMatch(message, matches, id: id, label)
        }
    }

    /// The archives it matches are every type the classifier names that conforms to `public.archive`, other than
    /// `public.archive` itself, a static library. The documents that are zips don't conform, and aren't. A type added
    /// to ``FileType/classified``, which the classifier's signatures are held to, has to be decided here.
    func testArchivesAreTheClassifiersArchives() throws {
        let archives = FileTypeIdentifierTests.identifiers.filter { identifier in
            identifier != UTType.archive.identifier && UTType(identifier)?.conforms(to: .archive) == true
        }
        XCTAssertEqual(Set(Indicator.archiveTypes.map(\.identifier)), archives)
        XCTAssertEqual(Indicator.archiveTypes.count, 13)
    }

    /// A write is stamped as the Security Extension stamps it: the indicator's name, low, Collection's T1560, shipped
    /// and unedited, and the verdict survives the wire.
    func testWriteIsStampedAsShippedLow() throws {
        let id = try shippedID("Archive written")
        var message = try derivedClose(at: "/Users/marcus/Library/Caches/loot.tgz", type: "org.gnu.gnu-zip-archive")
        var values = MessageValueCache()
        Self.shippedIndicators.stamp(&message, values: &values)
        let hit = try XCTUnwrap(message.indicators?.hits.first { $0.id == id })
        XCTAssertEqual(hit.name, "Archive written")
        XCTAssertEqual(hit.severity, .low)
        XCTAssertEqual(hit.tactic_id, "TA0009")
        XCTAssertEqual(hit.technique, "T1560")
        XCTAssertTrue(hit.isDefault)
        XCTAssertFalse(hit.edited)
        assertStamped(message.indicators)
        XCTAssertEqual(try JSONDecoder().decode(Message.self, from: JSONEncoder().encode(message)).indicators,
                       message.indicators)
    }

    /// The rule runs on closes alone, where the index looks it up by the file's type, exactly: the recorded close of a
    /// database's `-shm`, which is data, never evaluates it.
    func testRuleIsAnchoredOnTheTypes() throws {
        let indicator = try XCTUnwrap(Indicator.defaults.first { $0.name == "Archive written" })
        let rule = try IndicatorCompiler.compile(indicator.predicate).get()
        let close = Int(ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue)
        XCTAssertEqual(rule.types, [close])
        guard case .anyOf(let found) = rule.program.necessity(eventType: close) else {
            return XCTFail("Not anchored on closes")
        }
        let described = found.map { anchor in
            let bytes = rule.program.bytes[Int(anchor.offset)..<Int(anchor.offset + anchor.length)]
            return "\(anchor.field) \(anchor.shape) \(anchor.folding) \(String(decoding: bytes, as: UTF8.self))"
        }
        XCTAssertEqual(described, Indicator.archiveTypes.map { "closeFileType exact false \($0.identifier)" })
        let alone = CompiledIndicators([indicator])
        var values = MessageValueCache()
        for message in try fixtureMessages(Self.closeFixture) {
            XCTAssertEqual(alone.candidates(for: message, values: &values), [], message.target_path ?? "")
            let hits = Self.shippedIndicators.evaluate(message, values: &values).hits
            XCTAssertFalse(hits.contains { $0.id == indicator.id }, message.target_path ?? "")
        }
        let tar = try derivedClose(at: "/tmp/a", type: "public.tar-archive")
        XCTAssertEqual(alone.candidates(for: tar, values: &values), [0])
    }
}
