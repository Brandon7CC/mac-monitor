//
//  DiskImageWrittenTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/9/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Disk images written
/// Pins Archive written on the disk images build 86 didn't name, each made here by macOS 27's `hdiutil`, or
/// `diskutil image` for an Apple sparse image, and read as a capture lane reads a modified close's file
/// (``FileTypeReader``): read/write raw images with a GPT, an MBR or an Apple Partition Map, or with no partition map
/// an APFS container, an HFS+ or HFSX volume or a FAT or exFAT one, sparse and Apple sparse images, images encrypted
/// with AES-256 whatever their format, and a sparse bundle's `Info.plist` and its `Info.bckup` copy, XML or binary.
///
/// A sparse bundle's bands are the disk's blocks: the first is named a raw disk, and macOS's disk image daemons
/// writing it are left out, where anything else writing a file in a bands folder, or those daemons writing anywhere
/// else, still matches. The Security Extension's compiled set and Mac Monitor's own matching agree on every case.
final class DiskImageWrittenTests: XCTestCase {
    /// An image a tool makes, and what each file it writes should be named.
    fileprivate struct Made {
        /// What the case is.
        let label: String
        /// The tool's path.
        let tool: String
        /// Its arguments, given the image to make, beside the images made before it.
        let arguments: (_ image: String) -> [String]
        /// The image's name: a file, or a folder for a sparse bundle.
        let image: String
        /// Each file it writes, in the image, `""` for the image itself, the type its content should be named by, and
        /// whether Archive written should match its write.
        let files: [(path: String, type: String, matches: Bool)]
        /// The password `hdiutil` reads from its standard input, for an encrypted image.
        var password: String?
    }

    /// `hdiutil`'s path.
    private static let hdiutil = "/usr/bin/hdiutil"
    /// The code signing flags macOS 27.2 reports, through Endpoint Security, for a program re-signed adhoc:
    /// `CS_VALID`, `CS_ADHOC`, `CS_KILL`, `CS_NO_UNTRUSTED_HELPERS` and `CS_SIGNED`.
    private static let adhocFlags: Int64 = 0x2200_0203

    /// A blank image made with `hdiutil create`, of 1 MB unless its file system needs more.
    ///
    /// - Parameters:
    ///   - arguments: What to make, before the size, volume name and path.
    ///   - name: The image's name.
    ///   - type: The type its content should be named by.
    ///   - matches: Should Archive written match its write?
    ///   - size: The image's size, as `hdiutil` takes it.
    ///   - label: What the case is.
    /// - Returns: The case.
    private static func blank(_ arguments: [String], _ name: String, _ type: String, matches: Bool = true,
                              size: String = "1m", _ label: String) -> Made {
        Made(label: label, tool: hdiutil,
             arguments: { ["create", "-quiet"] + arguments + ["-size", size, "-volname", "Notes", $0] },
             image: name, files: [("", type, matches)])
    }

    /// The images the tools make, and the types the reader names them by.
    private static let made: [Made] = [
        blank(["-fs", "HFS+"], "gpt.dmg", "com.apple.disk-image-raw", "UDRW, GPT"),
        blank(["-layout", "NONE", "-fs", "APFS"], "apfs.dmg", "com.apple.disk-image-raw", "UDRW, APFS, no map"),
        blank(["-layout", "NONE", "-fs", "HFS+"], "hfs.dmg", "com.apple.disk-image-raw", "UDRW, HFS+, no map"),
        blank(["-layout", "NONE", "-fs", "HFSX"], "hfsx.dmg", "com.apple.disk-image-raw", "UDRW, HFSX, no map"),
        blank(["-layout", "NONE", "-fs", "MS-DOS"], "fat.dmg", "com.apple.disk-image-raw", "UDRW, FAT12, no map"),
        blank(["-layout", "MBRSPUD", "-fs", "MS-DOS"], "mbr.dmg", "com.apple.disk-image-raw", "UDRW, FAT12, MBR"),
        blank(["-fs", "MS-DOS FAT32"], "fat32.dmg", "com.apple.disk-image-raw", size: "33m", "UDRW, FAT32, MBR"),
        blank(["-layout", "NONE", "-fs", "ExFAT"], "exfat.dmg", "com.apple.disk-image-raw", "UDRW, exFAT, no map"),
        blank(["-fs", "ExFAT"], "exfat-mbr.dmg", "com.apple.disk-image-raw", "UDRW, exFAT, MBR"),
        blank(["-layout", "SPUD", "-fs", "HFS+"], "apm.dmg", "com.apple.disk-image-raw", "UDRW, Apple Partition Map"),
        blank(["-type", "SPARSE", "-fs", "APFS"], "sparse.sparseimage", "com.apple.disk-image-sparse", "SPARSE"),
        blank(["-type", "SPARSEBUNDLE", "-fs", "APFS"], "bundle.sparsebundle", "", "SPARSEBUNDLE").withFiles([
            ("Info.plist", "com.apple.disk-image-sparse-bundle", true),
            ("Info.bckup", "com.apple.disk-image-sparse-bundle", true),
        ]),
        blank(["-fs", "APFS", "-encryption", "AES-256", "-stdinpass"], "encrypted.dmg", "com.apple.disk-image",
              "UDRW, AES-256").withPassword(),
        blank(["-type", "SPARSE", "-fs", "APFS", "-encryption", "AES-256", "-stdinpass"], "encrypted.sparseimage",
              "com.apple.disk-image", "SPARSE, AES-256").withPassword(),
        Made(label: "UDZO, AES-256", tool: hdiutil,
             arguments: { ["convert", "-quiet", ($0 as NSString).deletingLastPathComponent + "/gpt.dmg", "-format",
                           "UDZO", "-encryption", "AES-256", "-stdinpass", "-o", $0] },
             image: "encrypted-udzo.dmg", files: [("", "com.apple.disk-image", true)], password: "notes"),
    ]

    /// Each image a tool makes is named by its content, and Archive written matches each, in the extension and in
    /// the app alike, with every indicator decided. The encrypted UDZO image is converted from the
    /// first, as `hdiutil create -srcfolder` takes seconds longer to make one.
    func testImagesAreIdentified() throws {
        let id = try shippedID("Archive written")
        let output = try resolvedTemporaryDirectory()
        let status = try run(Self.hdiutil, ["create", "-quiet", "-size", "1m", "-volname", "Notes",
                                            output + "/probe.dmg"])
        try XCTSkipUnless(status == 0, "hdiutil can't make disk images here")
        for made in Self.made {
            let image = output + "/" + made.image
            XCTAssertEqual(try run(made.tool, made.arguments(image), input: made.password), 0, made.label)
            for file in made.files {
                let path = file.path.isEmpty ? image : image + "/" + file.path
                try assertContentWrite(of: path, isNamed: file.type, matching: file.matches, id: id,
                                       made.label + " " + file.path)
            }
        }
    }

    /// A sparse bundle whose `Info.plist` and `Info.bckup` are converted to binary property lists, which macOS still
    /// attaches, is named for the bundle, and Archive written matches each.
    func testBinarySparseBundleIsIdentified() throws {
        let bundle = try resolvedTemporaryDirectory() + "/binary.sparsebundle"
        let status = try run(Self.hdiutil, ["create", "-quiet", "-type", "SPARSEBUNDLE", "-fs", "APFS", "-size", "1m",
                                            "-volname", "Notes", bundle])
        try XCTSkipUnless(status == 0, "hdiutil can't make disk images here")
        let id = try shippedID("Archive written")
        for file in ["Info.plist", "Info.bckup"] {
            let path = bundle + "/" + file
            XCTAssertEqual(try run("/usr/bin/plutil", ["-convert", "binary1", path]), 0, file)
            XCTAssertTrue(try Data(contentsOf: URL(fileURLWithPath: path)).starts(with: Data("bplist00".utf8)), file)
            try assertContentWrite(of: path, isNamed: "com.apple.disk-image-sparse-bundle", matching: true, id: id,
                                   "binary " + file)
        }
    }

    /// An Apple sparse image, which `diskutil image` makes, is a sparse image too.
    func testAppleSparseImageIsIdentified() throws {
        let image = try resolvedTemporaryDirectory() + "/notes.asif"
        let status = try run("/usr/sbin/diskutil", ["image", "create", "blank", "--fs", "None", "--format", "ASIF",
                                                    "--size", "1m", image])
        try XCTSkipUnless(status == 0, "diskutil can't make an Apple sparse image here")
        try assertContentWrite(of: image, isNamed: "com.apple.disk-image-sparse", matching: true,
                               id: try shippedID("Archive written"), "ASIF")
    }

    /// A sparse bundle's first band is a raw disk's start. macOS's disk image daemons writing a band don't match,
    /// nor a band of Time Machine's bundle, in any case, but a lookalike of one does, as do other programs writing
    /// in a bands folder and the daemons writing an image, or a folder only named `bands`. AppleScript written leaves
    /// bands out alike.
    func testSparseBundleBandsAreLeftOut() throws {
        let archive = try shippedID("Archive written")
        let bundle = try resolvedTemporaryDirectory() + "/Backups.sparsebundle"
        let status = try run(Self.hdiutil, ["create", "-quiet", "-type", "SPARSEBUNDLE", "-fs", "HFS+", "-size", "1m",
                                            "-volname", "Notes", bundle])
        try XCTSkipUnless(status == 0, "hdiutil can't make disk images here")
        let band = bundle + "/bands/0"
        try assertContentWrite(of: band, isNamed: "com.apple.disk-image-raw", matching: true, id: archive, "band 0")
        let raw = "com.apple.disk-image-raw"
        let cases: [(String, String, (String, Bool), Bool)] = [
            ("diskimagesiod's band", band, ("com.apple.diskimagesiod", true), false),
            ("diskimages-helper's band", band, ("com.apple.diskimages-helper", true), false),
            ("Time Machine's band", "/Volumes/Backups/Mac.backupbundle/bands/1a", ("com.apple.diskimagesiod", true),
             false),
            ("a band in any case", "/Users/marcus/Notes.SparseBundle/Bands/2", ("com.apple.diskimagesiod", true),
             false),
            ("a lookalike's band", band, ("com.apple.diskimagesiod", false), true),
            ("cp's band", band, ("com.apple.cp", true), true),
            ("diskimagesiod's image", "/Users/marcus/Downloads/loot.dmg", ("com.apple.diskimagesiod", true), true),
            ("diskimagesiod's bands folder", "/Users/marcus/bands/0", ("com.apple.diskimagesiod", true), true),
        ]
        for (label, path, process, matches) in cases {
            try assertShippedMatch(try derivedClose(at: path, type: raw, by: process), matches, id: archive, label)
        }
        let adhoc = adhocSigned(try derivedClose(at: band, type: raw, by: ("com.apple.diskimagesiod", true)))
        try assertShippedMatch(adhoc, true, id: archive, "an adhoc lookalike's band with checks off")
        let script = try derivedClose(at: band, type: FileType.compiledAppleScript.identifier,
                                      by: ("com.apple.diskimagesiod", true))
        try assertShippedMatch(script, false, id: try shippedID("AppleScript written"), "a band of a script's blocks")
    }

    /// The disk images Archive written matches, the UDIF image's among them.
    func testArchivesHoldEveryImage() {
        let images = ["com.apple.disk-image-udif", "com.apple.disk-image-raw", "com.apple.disk-image-sparse",
                      "com.apple.disk-image-sparse-bundle", "com.apple.disk-image"]
        XCTAssertTrue(Set(images).isSubset(of: Indicator.archiveTypes.map(\.identifier)))
        XCTAssertEqual(Indicator.diskImageDaemons, ["com.apple.diskimagesiod", "com.apple.diskimages-helper"])
    }
}


// MARK: - Making images
extension DiskImageWrittenTests {
    /// Run a tool, with its standard input given, and wait for it.
    ///
    /// - Parameters:
    ///   - tool: The tool's path.
    ///   - arguments: Its arguments.
    ///   - input: What it reads from its standard input, or `nil` for none.
    /// - Returns: Its exit status.
    /// - Throws: The error launching it or writing its input.
    private func run(_ tool: String, _ arguments: [String], input: String? = nil) throws -> Int32 {
        let process = Foundation.Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        let pipe = Pipe()
        process.standardInput = input == nil ? FileHandle.nullDevice : pipe
        try process.run()
        if let input {
            try pipe.fileHandleForWriting.write(contentsOf: Data(input.utf8))
            try pipe.fileHandleForWriting.close()
        }
        process.waitUntilExit()
        return process.terminationStatus
    }

    /// A close with its process made an adhoc signed one, as macOS reports a lookalike with its code signing checks
    /// off: a platform binary with `CS_ADHOC`, and what Mac Monitor derives from that derived again.
    ///
    /// - Parameter message: The close.
    /// - Returns: The close.
    private func adhocSigned(_ message: Message) -> Message {
        var message = message
        message.process.codesigning_flags = Self.adhocFlags
        message.process.is_platform_binary = true
        message.process.team_id = nil
        message.process.enrich()
        XCTAssertTrue(message.process.is_adhoc_signed)
        return message
    }
}

private extension DiskImageWrittenTests.Made {
    /// - Parameter files: Each file the image writes, the type it should be named by, and whether it should match.
    /// - Returns: The case with those files, rather than the image itself.
    func withFiles(_ files: [(path: String, type: String, matches: Bool)]) -> Self {
        Self(label: label, tool: tool, arguments: arguments, image: image, files: files, password: password)
    }

    /// - Returns: The case with a password given on `hdiutil`'s standard input.
    func withPassword() -> Self {
        Self(label: label, tool: tool, arguments: arguments, image: image, files: files, password: "notes")
    }
}
