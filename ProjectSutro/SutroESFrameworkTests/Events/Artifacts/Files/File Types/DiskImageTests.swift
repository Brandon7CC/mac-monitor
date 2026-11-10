//
//  DiskImageTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/9/26.
//

import XCTest
import MachO
@testable import SutroESFramework


// MARK: - Disk images by their bytes
/// Pins ``DiskImage`` through ``FileTypeClassifier`` on bytes made up for each image: encrypted, by its header or an
/// old one's trailer, sparse and Apple sparse, raw from a GPT, a FAT or exFAT boot sector, an Apple Partition Map, an
/// APFS container or an HFS+ volume, and a sparse bundle's `Info.plist`, XML or binary. And what else carries those
/// bytes stays what it is: text, other signatures, a near miss at each fixed offset, and bytes that end before the
/// offset.
final class DiskImageTests: XCTestCase {
    private typealias Samples = FileTypeSamples

    /// Assert a classification.
    ///
    /// - Parameters:
    ///   - header: The file's first bytes.
    ///   - identifier: The identifier expected.
    ///   - trailer: The file's last 512 bytes.
    ///   - line: The caller's line.
    private func assertType(_ header: [UInt8], _ identifier: String, trailer: [UInt8]? = nil, line: UInt = #line) {
        let type = FileTypeClassifier.classify(header: header, slice: nil, trailer: trailer)
        XCTAssertEqual(type.identifier, identifier, line: line)
    }

    /// 4 KB of zeros with bytes at an offset, as a raw disk is zeros but for its structures.
    ///
    /// - Parameters:
    ///   - bytes: The bytes.
    ///   - offset: Where they go.
    /// - Returns: The file's first bytes.
    private func zeros(with bytes: [UInt8], at offset: Int) -> [UInt8] {
        var header = [UInt8](repeating: 0, count: FileTypeClassifier.headerLength)
        header.replaceSubrange(offset..<(offset + bytes.count), with: bytes)
        return header
    }

    /// An APFS container superblock's start: its object header's type at 24, then `NXSB` at 32.
    ///
    /// - Parameter type: The object type, `OBJECT_TYPE_NX_SUPERBLOCK` with `OBJ_EPHEMERAL`, as `newfs_apfs` writes
    ///   it, by default.
    /// - Returns: The file's first bytes.
    private func container(type: UInt32 = 0x8000_0001) -> [UInt8] {
        zeros(with: Samples.word(type) + [0, 0, 0, 0] + Samples.text("NXSB"), at: 24)
    }

    // MARK: Signatures at the start

    /// An encrypted image starts with `encrcdsa`, whatever image it wraps; text that starts so stays text.
    func testEncryptedImage() {
        assertType(Samples.starting(with: Samples.text("encrcdsa") + [0, 0, 0, 2]), "com.apple.disk-image")
        assertType(Samples.text("encrcdsa is an encrypted image's header\n"), "public.plain-text")
        XCTAssertFalse(FileTypeClassifier.readsTrailer(for: .encryptedDiskImage))
    }

    /// An image of encryption's first version is data that ends with `cdsaencr`, in the trailer already read. Text
    /// with that trailer, a zip, and data with `cdsaencr` anywhere else in its trailer, keep their types.
    func testEncryptedImageOfTheFirstVersion() {
        let data = Samples.starting(with: [0xC3, 0x28, 0x00, 0x91])
        let trailer = [UInt8](repeating: 0xA5, count: 504) + Samples.text("cdsaencr")
        assertType(data, "com.apple.disk-image", trailer: trailer)
        assertType(Samples.text("notes\n"), "public.plain-text", trailer: trailer)
        assertType(Samples.starting(with: Samples.text("PK\u{03}\u{04}")), "public.zip-archive", trailer: trailer)
        assertType(data, "public.data", trailer: Samples.text("cdsaencr") + [UInt8](repeating: 0, count: 504))
        assertType(Samples.starting(with: [0x1F, 0x8B]), "org.gnu.gnu-zip-archive", trailer: trailer)
    }

    /// A sparse image starts with `sprs`, and an Apple sparse image with `shdw`, then their versions; text that
    /// starts so stays text.
    func testSparseImages() {
        assertType(Samples.starting(with: Samples.text("sprs") + Samples.word(3, bigEndian: true)),
                   "com.apple.disk-image-sparse")
        assertType(Samples.starting(with: Samples.text("shdw") + Samples.word(1, bigEndian: true)),
                   "com.apple.disk-image-sparse")
        assertType(Samples.text("sprs and shdw are sparse images' headers\n"), "public.plain-text")
        assertType(Samples.text("shdw\n"), "public.plain-text")
    }

    // MARK: Raw disks

    /// A FAT or exFAT volume: a boot sector, at 0 or after an MBR at 512, with its `0x55AA` at its 510 and its file
    /// system's name where the sector puts it. A name at another offset, a sector without its `0x55AA`, or an MBR
    /// whose next sector isn't a volume's, is data.
    func testFATVolumes() {
        let mbr = zeros(with: [0x55, 0xAA], at: 510)
        /// - Parameters:
        ///   - name: The file system's name.
        ///   - offset: Where it is in the sector.
        ///   - start: Where the sector starts.
        ///   - header: The bytes the sector is put in.
        /// - Returns: The bytes with a boot sector's jump, name and `0x55AA`.
        func sector(_ name: String, at offset: Int, from start: Int = 0, in header: [UInt8]? = nil) -> [UInt8] {
            var bytes = header ?? zeros(with: [], at: 0)
            bytes.replaceSubrange(start..<(start + 3), with: [0xEB, 0x3C, 0x90])
            bytes.replaceSubrange((start + offset)..<(start + offset + 8), with: Samples.text(name))
            bytes.replaceSubrange((start + 510)..<(start + 512), with: [0x55, 0xAA])
            return bytes
        }
        assertType(sector("EXFAT   ", at: 3), "com.apple.disk-image-raw")
        assertType(sector("FAT12   ", at: 54), "com.apple.disk-image-raw")
        assertType(sector("FAT16   ", at: 54), "com.apple.disk-image-raw")
        assertType(sector("FAT32   ", at: 82), "com.apple.disk-image-raw")
        assertType(sector("EXFAT   ", at: 3, from: 512, in: mbr), "com.apple.disk-image-raw")
        assertType(sector("FAT32   ", at: 82, from: 512, in: mbr), "com.apple.disk-image-raw")
        assertType(sector("FAT32   ", at: 54), "public.data")
        assertType(sector("FAT12   ", at: 82), "public.data")
        assertType(sector("EXFAT  ", at: 3), "public.data")
        var unsigned = sector("FAT12   ", at: 54)
        unsigned[510] = 0
        assertType(unsigned, "public.data")
        assertType(sector("FAT12   ", at: 54, from: 512), "public.data")
        var afterMBR = sector("FAT12   ", at: 54, from: 512, in: mbr)
        afterMBR[1_022] = 0
        assertType(afterMBR, "public.data")
    }

    /// An Apple Partition Map: its driver descriptor's `ER` at 0 and its first entry's `PM` at 512. Either alone is
    /// data, and so is an entry without its reserved bytes.
    func testApplePartitionMap() {
        let map = zeros(with: Samples.text("PM\0\0"), at: 512)
        assertType(Samples.text("ER") + [0x02, 0x00] + map.dropFirst(4), "com.apple.disk-image-raw")
        assertType(Samples.text("ER") + [0x02, 0x00] + zeros(with: [], at: 0).dropFirst(4), "public.data")
        assertType(map, "public.data")
        assertType(Samples.text("ER") + [0x02, 0x00] + zeros(with: Samples.text("PM\u{01}\0"), at: 512).dropFirst(4),
                   "public.data")
    }

    /// A GPT disk: the protective MBR's `0x55AA` at 510 and `EFI PART` at 512. Either alone is data.
    func testGPTDisk() {
        let gpt = [UInt8(0x55), 0xAA] + Samples.text("EFI PART")
        assertType(zeros(with: gpt, at: 510), "com.apple.disk-image-raw")
        assertType(zeros(with: [0x55, 0xAA], at: 510), "public.data")
        assertType(zeros(with: Samples.text("EFI PART"), at: 512), "public.data")
        assertType(zeros(with: [0x55, 0xAA] + Samples.text("EFI PARS"), at: 510), "public.data")
        assertType(zeros(with: gpt, at: 511), "public.data")
        assertType(Array(zeros(with: gpt, at: 510).prefix(519)), "public.data")
    }

    /// An APFS container with no partition map: `NXSB` at 32, where the object type's low 16 bits are 1, whatever
    /// its flags. Another object's `NXSB`, or the magic elsewhere, is data.
    func testAPFSContainer() {
        assertType(container(), "com.apple.disk-image-raw")
        assertType(container(type: 0x4000_0001), "com.apple.disk-image-raw")
        assertType(container(type: 0x8000_000D), "public.data")
        assertType(zeros(with: Samples.word(0x8000_0001) + [0, 0, 0, 0] + Samples.text("NXSB"), at: 28),
                   "public.data")
        assertType(Array(container().prefix(35)), "public.data")
    }

    /// An HFS+ volume with no partition map: `H+` version 4, or `HX` version 5, at 1024. Another version, or the
    /// signature elsewhere, is data.
    func testHFSVolume() {
        assertType(zeros(with: Samples.text("H+\0\u{04}"), at: 1_024), "com.apple.disk-image-raw")
        assertType(zeros(with: Samples.text("HX\0\u{05}"), at: 1_024), "com.apple.disk-image-raw")
        assertType(zeros(with: Samples.text("H+\0\u{05}"), at: 1_024), "public.data")
        assertType(zeros(with: Samples.text("HX\0\u{04}"), at: 1_024), "public.data")
        assertType(zeros(with: Samples.text("H+\0\u{04}"), at: 1_022), "public.data")
        assertType(Array(zeros(with: Samples.text("H+\0\u{04}"), at: 1_024).prefix(1_027)), "public.data")
    }

    /// A raw disk's bytes count only in data that has no other signature: text with `NXSB` at 32 stays text, as
    /// `0x55AA` isn't UTF-8 and an HFS+ version holds a NUL, and a Mach-O, a zip or a sparse image with a GPT's bytes
    /// keep their types.
    func testRawDiskBytesElsewhere() {
        let text = Samples.text(String(repeating: "a", count: 32) + "NXSB" + String(repeating: "b", count: 64))
        assertType(text, "public.plain-text")
        let gpt = zeros(with: [0x55, 0xAA] + Samples.text("EFI PART"), at: 510)
        var machO = gpt
        machO.replaceSubrange(0..<32, with: Samples.machO(MH_DYLIB).prefix(32))
        XCTAssertEqual(FileTypeClassifier.classify(header: machO).machOType, "MH_DYLIB")
        assertType(Samples.text("PK\u{03}\u{04}") + gpt.dropFirst(4), "public.zip-archive")
        assertType(Samples.text("sprs") + Samples.word(3, bigEndian: true) + gpt.dropFirst(8),
                   "com.apple.disk-image-sparse")
    }

    /// A raw disk's end is read, as a read-only UDIF image's first chunk is a raw disk's: a `koly` trailer makes it
    /// the UDIF image, and any other leaves it raw.
    func testRawDiskWithUDIFTrailer() {
        let gpt = zeros(with: [0x55, 0xAA] + Samples.text("EFI PART"), at: 510)
        XCTAssertTrue(FileTypeClassifier.readsTrailer(for: .rawDiskImage))
        assertType(gpt, "com.apple.disk-image-udif", trailer: Samples.diskImageTrailer)
        assertType(gpt, "com.apple.disk-image-raw", trailer: Array(gpt.suffix(512)))
        assertType(gpt, "com.apple.disk-image-raw", trailer: [UInt8](repeating: 0xA5, count: 504)
                    + Samples.text("cdsaencr"))
    }

    // MARK: Sparse bundles

    /// A sparse bundle's `Info.plist`, as `hdiutil` writes it, is named for the bundle, whatever surrounds its kind;
    /// a property list of another kind, or text that isn't one, holding its kind, isn't.
    func testSparseBundleInfo() {
        let info = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
            \t<key>CFBundleInfoDictionaryVersion</key>
            \t<string>6.0</string>
            \t<key>band-size</key>
            \t<integer>8388608</integer>
            \t<key>bundle-backingstore-version</key>
            \t<integer>1</integer>
            \t<key>diskimage-bundle-type</key>
            \t<string>com.apple.diskimage.sparsebundle</string>
            \t<key>size</key>
            \t<integer>1048576</integer>
            </dict>
            </plist>
            """
        assertType(Samples.text(info), "com.apple.disk-image-sparse-bundle")
        let other = info.replacingOccurrences(of: "com.apple.diskimage.sparsebundle",
                                              with: "com.apple.diskimage.sparse-bundle")
        assertType(Samples.text(other), "com.apple.xml-property-list")
        let bare = info.replacingOccurrences(of: "<string>com.apple.diskimage.sparsebundle</string>",
                                             with: "<string> com.apple.diskimage.sparsebundle </string>")
        assertType(Samples.text(bare), "com.apple.disk-image-sparse-bundle")
        assertType(Samples.text("Notes: <string>com.apple.diskimage.sparsebundle</string>\n"), "public.plain-text")
    }

    /// A sparse bundle's `Info.plist` converted to a binary property list, which `diskimagesiod` attaches as it
    /// does an XML one, is named for the bundle too; a binary property list of another kind isn't.
    func testSparseBundleBinaryInfo() throws {
        /// - Parameter kind: The bundle's kind.
        /// - Returns: The binary property list `plutil -convert binary1` makes of a bundle's `Info.plist`.
        func info(_ kind: String) throws -> [UInt8] {
            let plist: [String: Any] = ["CFBundleInfoDictionaryVersion": "6.0", "band-size": 8_388_608,
                                        "bundle-backingstore-version": 1, "diskimage-bundle-type": kind,
                                        "size": 1_048_576]
            return try Array(PropertyListSerialization.data(fromPropertyList: plist, format: .binary, options: 0))
        }
        assertType(try info("com.apple.diskimage.sparsebundle"), "com.apple.disk-image-sparse-bundle")
        assertType(try info("com.apple.diskimage.sparse-bundle"), "com.apple.binary-property-list")
    }

    /// The byte search a sparse bundle's mark and a property list's take, in an array and in a slice of one.
    func testHolds() {
        let bytes = Samples.text("one two three")
        XCTAssertTrue(bytes.holds(Samples.text("three")))
        XCTAssertTrue(bytes.holds(Samples.text("one")))
        XCTAssertFalse(bytes.holds(Samples.text("four")))
        XCTAssertFalse(bytes.holds(Samples.text("three!")))
        XCTAssertTrue(bytes.holds([]))
        XCTAssertFalse(bytes.dropFirst(1).holds(Samples.text("one")))
        XCTAssertTrue(bytes.dropFirst(4).holds(Samples.text("two")))
        XCTAssertFalse([UInt8]().holds(Samples.text("a")))
    }
}
