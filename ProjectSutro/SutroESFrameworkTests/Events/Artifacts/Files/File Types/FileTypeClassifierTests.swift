//
//  FileTypeClassifierTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
import MachO
@testable import SutroESFramework


// MARK: - Classifying bytes
/// Pins ``FileTypeClassifier`` on bytes made up for each kind of file: Mach-O by file type in both byte orders,
/// universal binaries and Java classes, scripts by interpreter, archives, disk images, property lists, text and data.
final class FileTypeClassifierTests: XCTestCase {
    private typealias Samples = FileTypeSamples

    /// Classify a file's first bytes.
    ///
    /// - Parameters:
    ///   - header: The bytes.
    ///   - slice: A universal binary's first slice's header, read on its own.
    ///   - trailer: The file's last 512 bytes.
    /// - Returns: The identifier and the Mach-O file type.
    private func classify(_ header: [UInt8], slice: [UInt8]? = nil,
                          trailer: [UInt8]? = nil) -> (String, String?) {
        let type = FileTypeClassifier.classify(header: header, slice: slice, trailer: trailer)
        return (type.identifier, type.machOType)
    }

    /// A zip's first local file header and what follows its name.
    ///
    /// - Parameters:
    ///   - name: The first entry's name.
    ///   - method: Its compression method: 0 is stored, 8 deflated.
    ///   - extra: The length of its extra field, of zeros.
    ///   - content: The entry's first bytes.
    /// - Returns: The bytes.
    private func zipEntry(_ name: String, method: UInt16 = 0, extra: UInt16 = 0, content: String = "") -> [UInt8] {
        let little = { (value: UInt16) in [UInt8(value & 0xFF), UInt8(value >> 8)] }
        let fixed = Samples.text("PK\u{03}\u{04}") + [0x14, 0, 0, 0] + little(method) + [UInt8](repeating: 0, count: 16)
        return fixed + little(UInt16(name.utf8.count)) + little(extra) + Samples.text(name)
            + [UInt8](repeating: 0, count: Int(extra)) + Samples.text(content)
    }

    /// Assert a classification.
    ///
    /// - Parameters:
    ///   - header: The bytes.
    ///   - identifier: The identifier expected.
    ///   - machOType: The Mach-O file type expected.
    ///   - slice: A universal binary's first slice's header.
    ///   - trailer: The file's last 512 bytes.
    ///   - line: The caller's line.
    private func assertType(_ header: [UInt8], _ identifier: String, _ machOType: String? = nil,
                            slice: [UInt8]? = nil, trailer: [UInt8]? = nil, line: UInt = #line) {
        let (actual, type) = classify(header, slice: slice, trailer: trailer)
        XCTAssertEqual(actual, identifier, line: line)
        XCTAssertEqual(type, machOType, line: line)
    }

    // MARK: Mach-O

    /// Each file type has its identifier, or the Mach-O binary one, and its `MH_*` name.
    func testThinMachOByFileType() {
        let expected: [(Int32, String, String)] = [
            (MH_EXECUTE, "com.apple.mach-o-executable", "MH_EXECUTE"), (MH_DYLIB, "com.apple.mach-o-dylib", "MH_DYLIB"),
            (MH_BUNDLE, "com.apple.mach-o-bundle", "MH_BUNDLE"), (MH_OBJECT, "com.apple.mach-o-object", "MH_OBJECT"),
            (MH_CORE, "com.apple.mach-o-core", "MH_CORE"), (MH_DYLINKER, "com.apple.mach-o-binary", "MH_DYLINKER"),
            (MH_KEXT_BUNDLE, "com.apple.mach-o-binary", "MH_KEXT_BUNDLE"),
            (MH_FILESET, "com.apple.mach-o-binary", "MH_FILESET"), (MH_DSYM, "com.apple.mach-o-binary", "MH_DSYM"),
            (MH_DYLIB_STUB, "com.apple.mach-o-binary", "MH_DYLIB_STUB"), (0x1F, "com.apple.mach-o-binary", "0x1f"),
        ]
        for (fileType, identifier, name) in expected {
            assertType(Samples.machO(fileType), identifier, name)
        }
    }

    /// 32-bit and 64-bit headers in either byte order.
    func testThinMachOWidthsAndByteOrders() {
        for wide in [true, false] {
            for bigEndian in [true, false] {
                assertType(Samples.machO(MH_EXECUTE, wide: wide, bigEndian: bigEndian),
                           "com.apple.mach-o-executable", "MH_EXECUTE")
            }
        }
    }

    /// A header cut short before its `filetype` is a Mach-O binary without a file type.
    func testMachOCutShort() {
        assertType(Array(Samples.machO(MH_DYLIB).prefix(8)), "com.apple.mach-o-binary")
    }

    /// A universal binary is its first slice's type, from the sample when the slice starts in it, else from the slice's
    /// own header, which is where the reader is told to read it.
    func testUniversalBinaryIsItsFirstSlice() {
        assertType(Samples.universal(with: Samples.machO(MH_DYLIB)), "com.apple.mach-o-dylib", "MH_DYLIB")
        let header = Samples.universal(sliceAt: 16_384)
        XCTAssertEqual(FileTypeClassifier.sliceOffsetToRead(header: header), 16_384)
        XCTAssertNil(FileTypeClassifier.sliceOffsetToRead(header: Samples.universal(with: Samples.machO(MH_DYLIB))))
        assertType(header, "com.apple.mach-o-executable", "MH_EXECUTE", slice: Samples.machO(MH_EXECUTE))
        let wide = Samples.universal(sliceAt: 32_768, wide: true)
        XCTAssertEqual(FileTypeClassifier.sliceOffsetToRead(header: wide), 32_768)
        assertType(wide, "com.apple.mach-o-bundle", "MH_BUNDLE", slice: Samples.machO(MH_BUNDLE))
        assertType(Samples.universal(sliceAt: 16_384, bigEndian: false), "com.apple.mach-o-dylib", "MH_DYLIB",
                   slice: Samples.machO(MH_DYLIB))
    }

    /// A universal static library, whose slice is an `ar` archive, is an archive. One whose slice couldn't be read, or
    /// with no slices, is a Mach-O binary.
    func testUniversalBinaryWithoutAMachOSlice() {
        assertType(Samples.universal(sliceAt: 16_384), "public.archive",
                   slice: Samples.starting(with: Samples.text("!<arch>\n")))
        assertType(Samples.universal(sliceAt: 16_384), "com.apple.mach-o-binary")
        assertType(Samples.universal(sliceAt: 16_384), "com.apple.mach-o-binary", slice: [])
        assertType(Samples.universal(sliceAt: 16_384, count: 0), "com.apple.mach-o-binary")
    }

    /// A Java class shares `0xCAFEBABE`: its version (Java 8's 52, with a minor version or not) is where a universal
    /// header has a small slice count.
    func testJavaClass() {
        let java8 = Samples.word(0xCAFE_BABE, bigEndian: true) + [0, 0, 0, 52]
        assertType(Samples.starting(with: java8), "com.sun.java-class")
        assertType(Samples.starting(with: Samples.word(0xCAFE_BABE, bigEndian: true) + [0, 3, 0, 45]),
                   "com.sun.java-class")
        XCTAssertNil(FileTypeClassifier.sliceOffsetToRead(header: Samples.starting(with: java8)))
        assertType(Samples.universal(with: Samples.machO(MH_EXECUTE)), "com.apple.mach-o-executable", "MH_EXECUTE")
        /// 300 constants, then a method reference: a count's high byte of 1 is where a CPU type's ABI bits are.
        let constants = java8 + [0x01, 0x2C, 0x0A, 0x00, 0x02, 0x00, 0x03]
        assertType(Samples.starting(with: constants), "com.sun.java-class")
    }

    /// The CPU types the universal tests name slices by.
    private let arm64 = UInt32(bitPattern: CPU_TYPE_ARM64), x86_64 = UInt32(bitPattern: CPU_TYPE_X86_64)

    /// A universal header's offsets come from the file: one past `Int64.max`, where `pread` can't read and adding a
    /// header's length would overflow, names no slice to read, and the binary is a Mach-O binary without a file type.
    /// A 32-bit offset can't overflow, and is read where it says.
    func testHugeSliceOffsets() {
        for offset in [UInt64.max, UInt64.max - 16, UInt64.max - 31, UInt64(Int64.max)] {
            let header = Samples.universal(slices: [(arm64, offset)], wide: true)
            XCTAssertNil(MachOHeader.sliceOffset(header), "\(offset)")
            XCTAssertNil(FileTypeClassifier.sliceOffsetToRead(header: header), "\(offset)")
            assertType(header, "com.apple.mach-o-binary")
            assertType(Samples.starting(with: header, length: 4_096), "com.apple.mach-o-binary")
        }
        let below = UInt64(Int64.max) - 1
        XCTAssertEqual(FileTypeClassifier.sliceOffsetToRead(header: Samples.universal(slices: [(arm64, below)],
                                                                                      wide: true)), below)
        let narrow = Samples.universal(slices: [(arm64, UInt64(UInt32.max))])
        XCTAssertEqual(FileTypeClassifier.sliceOffsetToRead(header: narrow), UInt64(UInt32.max))
        assertType(narrow, "com.apple.mach-o-binary")
    }

    /// A universal binary padded to 45 slices or more is still universal: its first entry's CPU type is known, where
    /// a Java class has its constant pool. A count past what the kernel reads (204 `fat_arch`) names no slice: it's a
    /// Java class when it's where a class's version would be, else a Mach-O binary.
    func testManySlicesArentAJavaClass() {
        let junk = (1..<45).map { _ in (cpu: UInt32(0xDEAD_BEEF), offset: UInt64(0)) }
        let padded = Samples.universal(slices: [(arm64, 16_384)] + junk)
        XCTAssertFalse(MachOHeader.isJavaClass(padded))
        XCTAssertEqual(FileTypeClassifier.sliceOffsetToRead(header: padded, preferring: arm64), 16_384)
        assertType(padded, "com.apple.mach-o-executable", "MH_EXECUTE", slice: Samples.machO(MH_EXECUTE))
        let most = Samples.universal(slices: [(arm64, 16_384)], count: 204)
        XCTAssertEqual(FileTypeClassifier.sliceOffsetToRead(header: most), 16_384)
        let tooMany = Samples.universal(slices: [(arm64, 16_384)], count: 205)
        XCTAssertNil(FileTypeClassifier.sliceOffsetToRead(header: tooMany))
        assertType(tooMany, "com.sun.java-class")
        let minorVersion = Samples.universal(slices: [(arm64, 16_384)], count: 0x0001_0000)
        XCTAssertNil(FileTypeClassifier.sliceOffsetToRead(header: minorVersion))
        assertType(minorVersion, "com.apple.mach-o-binary")
    }

    /// A universal binary is named by the slice this Mac runs, as the kernel picks it, so a first slice of another
    /// kind can't hide it. Without one for the CPU, it's its first slice.
    func testUniversalBinaryIsTheHostsSlice() {
        let header = Samples.universal(slices: [(x86_64, 16_384), (arm64, 32_768)])
        XCTAssertEqual(FileTypeClassifier.sliceOffsetToRead(header: header, preferring: arm64), 32_768)
        XCTAssertEqual(FileTypeClassifier.sliceOffsetToRead(header: header, preferring: x86_64), 16_384)
        XCTAssertEqual(FileTypeClassifier.sliceOffsetToRead(header: header,
                                                            preferring: UInt32(bitPattern: CPU_TYPE_POWERPC)), 16_384)
        /// Both slices inside the sample: an object first, then an arm64 executable.
        var inside = Samples.universal(slices: [(x86_64, 128), (arm64, 256)])
        inside += [UInt8](repeating: 0, count: 128 - inside.count) + Samples.machO(MH_OBJECT)
        inside += [UInt8](repeating: 0, count: 256 - inside.count) + Samples.machO(MH_EXECUTE)
        XCTAssertEqual(FileTypeClassifier.classify(header: inside, preferring: arm64),
                       FileType("com.apple.mach-o-executable", machOType: "MH_EXECUTE"))
        XCTAssertEqual(FileTypeClassifier.classify(header: inside, preferring: x86_64),
                       FileType("com.apple.mach-o-object", machOType: "MH_OBJECT"))
        #if arch(arm64)
        XCTAssertEqual(MachOHeader.hostCPU, arm64)
        #else
        XCTAssertEqual(MachOHeader.hostCPU, x86_64)
        #endif
    }

    /// Only a known CPU type with no ABI bits, `CPU_ARCH_ABI64` or `CPU_ARCH_ABI64_32` names a slice.
    func testKnownCPUTypes() {
        for cpu in [CPU_TYPE_ARM64, CPU_TYPE_X86_64, CPU_TYPE_ARM, CPU_TYPE_X86, CPU_TYPE_POWERPC,
                    CPU_TYPE_POWERPC64, CPU_TYPE_ARM64_32] {
            XCTAssertTrue(MachOHeader.isKnownCPU(UInt32(bitPattern: cpu)), "\(cpu)")
        }
        for cpu: UInt32 in [0, 0xDEAD_BEEF, 0x0100_0000, 0x012C_0A00, 0x0400_000C, 0x0000_0A07] {
            XCTAssertFalse(MachOHeader.isKnownCPU(cpu), "\(cpu)")
        }
    }

    // MARK: Scripts

    /// A script is named by its interpreter's last path component, or the word `env` runs.
    func testScriptsByInterpreter() {
        let expected = [
            "#!/bin/sh": "public.shell-script", "#!/bin/bash -e": "public.bash-script",
            "#!/bin/zsh": "public.zsh-script", "#!/bin/csh -f": "public.csh-script",
            "#!/bin/tcsh": "public.tcsh-script", "#!/bin/ksh": "public.ksh-script",
            "#! /usr/bin/python3": "public.python-script", "#!/usr/local/bin/python3.12": "public.python-script",
            "#!/usr/bin/pythonw": "public.python-script", "#!/usr/bin/perl -w": "public.perl-script",
            "#!/usr/bin/perl5.34": "public.perl-script", "#!/usr/bin/ruby": "public.ruby-script",
            "#!/usr/local/bin/node": "com.netscape.javascript-source",
            "#!/opt/homebrew/bin/bun": "com.netscape.javascript-source",
            "#!/usr/bin/osascript": "com.apple.applescript.text",
            "#!/usr/bin/osascript -l JavaScript": "com.netscape.javascript-source",
            "#!/usr/bin/env python3": "public.python-script", "#!/usr/bin/env -S ruby -w": "public.ruby-script",
            "#!/usr/bin/env -i PATH=/bin bash": "public.bash-script", "#!/usr/bin/env -u HOME zsh": "public.zsh-script",
            "#!/usr/bin/env\tnode": "com.netscape.javascript-source", "#!/bin/dash": "public.script",
            "#!/usr/bin/awk -f": "public.script", "#!/usr/bin/env": "public.script", "#!": "public.script",
        ]
        for (line, identifier) in expected {
            assertType(Samples.text(line + "\necho hi\n"), identifier)
        }
        assertType(Samples.text("#!/bin/zsh\r\necho hi"), "public.zsh-script")
    }

    /// A shell header with a binary payload after it, as a self-extracting installer has, is still a script.
    func testScriptWithAPayload() {
        assertType(Samples.text("#!/bin/sh\nexit 0\n") + [0, 0xFF, 0x1F, 0x8B], "public.shell-script")
    }

    /// Compiled AppleScript and JXA, which `osacompile` writes: its header's bytes that aren't text follow the magic.
    /// Text that starts with either magic is text.
    func testCompiledAppleScript() {
        assertType(Samples.starting(with: Samples.text("FasdUAS 1.101.10")), "com.apple.applescript.script")
        assertType(Samples.text("JsOsaDAS1.001.00bplist00") + [0xD1, 0x01, 0x02], "com.apple.applescript.script")
        assertType(Samples.text("FasdUAS 1.101.10\nset n to 1\n"), "public.plain-text")
        assertType(Samples.text("JsOsaDAS is not a script\n"), "public.plain-text")
    }

    // MARK: Archives and disk images

    /// Each archive's signature.
    func testArchives() {
        let expected: [([UInt8], String)] = [
            ([0x50, 0x4B, 0x03, 0x04], "public.zip-archive"), ([0x50, 0x4B, 0x05, 0x06], "public.zip-archive"),
            ([0x50, 0x4B, 0x07, 0x08], "public.zip-archive"), (Samples.text("xar!"), "com.apple.xar-archive"),
            ([0x1F, 0x8B, 0x08], "org.gnu.gnu-zip-archive"), (Samples.text("BZh91AY"), "public.bzip2-archive"),
            ([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], "org.tukaani.xz-archive"),
            ([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], "org.7-zip.7-zip-archive"),
            (Samples.text("AA01"), "com.apple.archive"), (Samples.text("YAA1"), "com.apple.archive"),
            (Samples.text("!<arch>\n"), "public.archive"),
        ]
        for (signature, identifier) in expected {
            assertType(Samples.starting(with: signature), identifier)
        }
        assertType(Samples.tarHeader, "public.tar-archive")
    }

    /// A zip whose first entry an Office Open XML package, OpenDocument or EPUB puts first is that document, not an
    /// archive. Any other first entry, a compressed `mimetype`, another MIME type, an extra field before the MIME
    /// type, and a header cut short leave it a zip.
    func testZipDocuments() {
        let documents: [([UInt8], String)] = [
            (zipEntry("[Content_Types].xml", method: 8), "org.openxmlformats.openxml"),
            (zipEntry("_rels/.rels", method: 8), "org.openxmlformats.openxml"),
            (zipEntry("mimetype", content: "application/vnd.oasis.opendocument.text"), "org.oasis-open.opendocument"),
            (zipEntry("mimetype", extra: 4, content: "application/epub+zip"), "org.idpf.epub-container"),
            (zipEntry("notes.txt", method: 8), "public.zip-archive"),
            (zipEntry("[Content_Types].xm"), "public.zip-archive"),
            (zipEntry("mimetype", method: 8, content: "application/epub+zip"), "public.zip-archive"),
            (zipEntry("mimetype", content: "application/zip"), "public.zip-archive"),
            (zipEntry("mimetypes", content: "application/epub+zip"), "public.zip-archive"),
            (Array(zipEntry("[Content_Types].xml").prefix(40)), "public.zip-archive"),
        ]
        for (header, identifier) in documents {
            assertType(header, identifier)
        }
    }

    /// `aa archive` compresses by default: an Apple Archive is then its algorithm's stream, LZFSE, LZ4, zlib or
    /// LZBITMAP, each with its block size after it. LZMA's `pbzx`, which a package's `Payload` is too, is data.
    func testCompressedAppleArchives() {
        let blockSize: [UInt8] = [0, 0, 0, 0, 0, 0x40, 0, 0]
        for magic in ["pbze", "pbz4", "pbzz", "pbzb"] {
            assertType(Samples.starting(with: Samples.text(magic) + blockSize), "com.apple.archive")
        }
        assertType(Samples.starting(with: Samples.text("pbzx") + blockSize), "public.data")
    }

    /// A signature of printable characters counts only in bytes that aren't text: a CSV, notes or a log that start
    /// with one stay text, where the archives themselves have binary bytes after it.
    func testPrintableSignaturesInText() {
        for text in ["AA01,ID,Name\n1,2,3\n", "YAA1 notes", "xar! notes", "BZh9 is a bzip2 header\n",
                     "pbze is LZFSE\n"] {
            assertType(Samples.text(text), "public.plain-text")
        }
        assertType(Samples.text("xar!") + [0x00, 0x1C, 0x00, 0x01], "com.apple.xar-archive")
        assertType(Samples.text("AA01") + [0x3A, 0x00] + Samples.text("TYP1F"), "com.apple.archive")
    }

    /// A UDIF image is named by its trailer, when its first bytes are data or a compressed stream its first chunk can
    /// be. Text, or an archive no image starts with, keeps its type, and with no trailer read, so does data.
    func testDiskImage() {
        let trailer = Samples.diskImageTrailer
        assertType(Samples.starting(with: [0x78, 0xDA, 0x01]), "com.apple.disk-image-udif", trailer: trailer)
        assertType(Samples.starting(with: Samples.text("BZh91AY")), "com.apple.disk-image-udif", trailer: trailer)
        assertType(Samples.starting(with: [0x1F, 0x8B]), "com.apple.disk-image-udif", trailer: trailer)
        assertType(Samples.text("plain text"), "public.plain-text", trailer: trailer)
        assertType(Samples.starting(with: [0x50, 0x4B, 0x03, 0x04]), "public.zip-archive", trailer: trailer)
        assertType(Samples.starting(with: [0x78, 0xDA, 0x01]), "public.data")
        assertType(Samples.starting(with: [0x78, 0xDA, 0x01]), "public.data",
                   trailer: Samples.starting(with: Samples.text("kolx"), length: 512))
        XCTAssertTrue(FileTypeClassifier.readsTrailer(for: .data))
        XCTAssertFalse(FileTypeClassifier.readsTrailer(for: .plainText))
        XCTAssertFalse(FileTypeClassifier.readsTrailer(for: FileType("com.apple.mach-o-dylib", machOType: "MH_DYLIB")))
    }

    // MARK: Others

    /// ELF, PE, property lists, PDF and the dyld shared cache.
    func testOtherSignatures() {
        assertType(Samples.starting(with: [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01]), "public.elf-binary")
        assertType(Samples.starting(with: Samples.text("bplist00")), "com.apple.binary-property-list")
        assertType(Samples.text("%PDF-1.7\n%\u{E2}\n"), "com.adobe.pdf")
        assertType(Samples.starting(with: Samples.text("dyld_v1  arm64e")), "dyld_shared_cache")
    }

    /// A PE has `PE\0\0` where `e_lfanew` points. An `MZ` without one is an executable only when it isn't text.
    func testWindowsExecutable() {
        var pe = Samples.starting(with: Samples.text("MZ"), length: 256)
        pe.replaceSubrange(0x3C..<0x40, with: Samples.word(0x80))
        pe.replaceSubrange(0x80..<0x84, with: Samples.text("PE\0\0"))
        assertType(pe, "com.microsoft.windows-executable")
        assertType(Samples.starting(with: Samples.text("MZ"), length: 32), "com.microsoft.windows-executable")
        assertType(Samples.text("MZ is a postal code"), "public.plain-text")
    }

    /// An XML property list by its root element or DOCTYPE, after a byte order mark and white space. Other XML is text.
    func testXMLPropertyList() {
        let plist = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict/></plist>
            """
        assertType(Samples.text(plist), "com.apple.xml-property-list")
        assertType([0xEF, 0xBB, 0xBF] + Samples.text("\n  <plist version=\"1.0\"><dict/></plist>"),
                   "com.apple.xml-property-list")
        assertType(Samples.text("<?xml version=\"1.0\"?>\n<!DOCTYPE plist SYSTEM \"x.dtd\">"),
                   "com.apple.xml-property-list")
        assertType(Samples.text("<?xml version=\"1.0\"?>\n<feed></feed>"), "public.plain-text")
        assertType(Samples.text("Notes on <plist> files"), "public.plain-text")
    }

    /// Valid UTF-8 without a NUL is text, even cut mid-character at 4 KB. Anything else is data. No bytes is empty.
    func testTextAndData() {
        assertType(Samples.text("hello, world\n"), "public.plain-text")
        assertType(Samples.text("caf\u{E9} \u{1F600}"), "public.plain-text")
        let cut = Array((Samples.text(String(repeating: "a", count: 4_094)) + Samples.text("\u{1F600}")).prefix(4_096))
        XCTAssertEqual(cut.count, FileTypeClassifier.headerLength)
        assertType(cut, "public.plain-text")
        assertType(Array(cut.prefix(4_095)) + [0x61], "public.data")
        assertType(Samples.text("text") + [0xFF, 0x61], "public.data")
        assertType(Samples.text("text\0more"), "public.data")
        assertType([], "empty")
    }

    /// Text is checked in place, eight bytes at a time, and the answer is always the decoder's: for bytes of every
    /// kind (ASCII, NUL, each length of character, lone continuation bytes, overlong and surrogate encodings), in
    /// runs of every length across a word's end, whole and as a slice that doesn't start at zero.
    func testTextCheckedInPlaceIsTheDecoders() {
        let pieces: [[UInt8]] = [
            Array("a".utf8), Array("plain text, ".utf8), [0x00], Array("\u{E9}".utf8), Array("\u{20AC}".utf8),
            Array("\u{1F600}".utf8), [0x80], [0xC3], [0xC0, 0x80], [0xED, 0xA0, 0x80], [0xF4, 0x90, 0x80, 0x80],
            [0xFF], [0x7F], [0x0A],
        ]
        var samples: [[UInt8]] = [[], [0x00], Array("12345678".utf8), Array("1234567".utf8) + [0x00]]
        for length in 0...40 {
            samples.append(Array(repeating: UInt8(ascii: "x"), count: length))
            for piece in pieces {
                samples.append(Array(repeating: UInt8(ascii: "x"), count: length) + piece)
                samples.append(Array(repeating: UInt8(ascii: "x"), count: length) + piece + Array("tail".utf8))
            }
        }
        samples += (0..<3_000).map { _ in
            (0..<Int.random(in: 0...12)).flatMap { _ in pieces.randomElement()! }
        }
        for sample in samples {
            let expected = FileTypeClassifier.decodesAsText(sample)
            XCTAssertEqual(FileTypeClassifier.isText(sample), expected, "\(sample)")
            let padded = [0xFF, 0x00, 0x41] + sample
            XCTAssertEqual(FileTypeClassifier.isText(padded[3...]), expected, "As a slice: \(sample)")
        }
        /// A header cut at its length mid-character is text up to the cut, whichever way it's checked.
        let cut = Array((Samples.text(String(repeating: "a", count: 4_094)) + Samples.text("\u{1F600}")).prefix(4_096))
        XCTAssertTrue(FileTypeClassifier.isText(cut))
        XCTAssertFalse(FileTypeClassifier.decodesAsText(cut), "The cut character alone doesn't decode")
    }
}
