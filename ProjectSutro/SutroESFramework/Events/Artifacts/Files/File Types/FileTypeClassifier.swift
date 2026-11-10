//
//  FileTypeClassifier.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation


// MARK: - Classifying a file's content
/// A file's type from its bytes alone: the first ``headerLength``, a universal binary's slice's header, and a disk
/// image's trailer. No I/O: ``FileTypeReader`` reads the bytes.
///
/// Signatures are checked first (Mach-O, scripts, archives, disk images, property lists, PDF, ELF and PE), with a
/// zip's first entry for the documents that are zips (``ZipDocument``), then the text a file holds: an XML property
/// list, else plain text, else data, or a raw disk image's when its bytes at fixed offsets are a disk's. A property
/// list, XML or binary, that names a sparse bundle is that bundle's `Info.plist`. A signature of printable characters
/// (`xar!`, `BZh9`, `AA01`, `FasdUAS`, `sprs`) counts only when the bytes aren't text, so a CSV whose first record is
/// `AA01,...` stays text. A file whose header is data, a raw disk, or a compressed stream that a UDIF image's first
/// chunk can be (gzip, bzip2, xz), is a UDIF image when its last 512 bytes start with `koly`, and data is an encrypted
/// image when they end with `cdsaencr` (``DiskImage``).
enum FileTypeClassifier {
    /// How many bytes of a file are sampled from its start.
    static let headerLength = 4_096
    /// How many bytes of a file's end hold a UDIF image's trailer (`UDIFResourceFile`).
    static let trailerLength = 512

    /// A signature at a file's start, the type it means, and whether it counts only in bytes that aren't text: one
    /// of printable characters that a text file could start with too.
    private typealias Signature = (bytes: [UInt8], type: FileType, binary: Bool)

    /// The signatures a file starts with, other than Mach-O's and a script's.
    ///
    /// A compiled script is `FasdUAS` for AppleScript and `JsOsaDAS` for JXA, whatever `osacompile` was asked for: a
    /// `.scpt`, a script bundle's or an applet's `main.scpt`, run-only or not. Bytes that aren't text follow each.
    ///
    /// An Apple Archive is `AA01` or `YAA1` uncompressed, and `aa archive` compresses by default: then it's the stream
    /// magic of its algorithm, `pbze` (LZFSE), `pbz4` (LZ4), `pbzz` (zlib) or `pbzb` (LZBITMAP). LZMA's `pbzx` is left
    /// out: a package's `Payload` is a `pbzx` stream too, of a `cpio` archive.
    private static let signatures: [Signature] = [
        (Array("dyld_v1".utf8), .dyldCache, false),
        (Array("FasdUAS".utf8), .compiledAppleScript, true), (Array("JsOsaDAS".utf8), .compiledAppleScript, true),
        (Array("PK\u{03}\u{04}".utf8), .zip, false), (Array("PK\u{05}\u{06}".utf8), .zip, false),
        (Array("PK\u{07}\u{08}".utf8), .zip, false),
        (Array("xar!".utf8), .xar, true),
        ([0x1F, 0x8B], .gzip, false),
        ([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], .xz, false),
        ([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], .sevenZip, false),
        ([0x7F, 0x45, 0x4C, 0x46], .elf, false),
        (Array("bplist00".utf8), .binaryPropertyList, false),
        (Array("%PDF-".utf8), .pdf, false),
        (MachOHeader.archiveMagic, .archive, false),
    ] + ["AA01", "YAA1", "pbze", "pbz4", "pbzz", "pbzb"].map { (Array($0.utf8), .appleArchive, true) }
        + (1...9).map { (Array("BZh\($0)".utf8), .bzip2, true) }
        + DiskImage.signatures.map { ($0.bytes, $0.type, true) }
    /// A POSIX tar header's `ustar` magic, 257 bytes in.
    private static let tarMagic = (bytes: Array("ustar".utf8), offset: 257)
    /// A UTF-8 byte order mark.
    private static let byteOrderMark: [UInt8] = [0xEF, 0xBB, 0xBF]
    /// What an XML property list has in its first bytes: its root element or its DOCTYPE.
    private static let propertyListMarks = [Array("<plist".utf8), Array("<!DOCTYPE plist".utf8)]

    /// The types a signature, or a zip's first entry, names: each must be in ``FileType/classified``.
    static var signatureTypes: Set<FileType> {
        Set(signatures.map(\.type) + ZipDocument.types)
    }

    /// A file's type from its first bytes and, for a universal binary, its slice's. The disk image check needs the
    /// file's end: ``classify(_:trailer:)``.
    ///
    /// - Parameters:
    ///   - header: The file's first bytes, up to ``headerLength``.
    ///   - slice: A universal binary's slice's first bytes (``MachOHeader/sliceHeaderLength``), or `nil` to take them
    ///     from `header` when the slice starts inside it.
    ///   - cpu: The CPU type whose slice a universal binary is named by, else its first slice's: this Mac's.
    /// - Returns: The type: ``FileType/empty`` for no bytes, else a type identifier and, for a Mach-O, its file type.
    static func classify<Bytes: ByteSample>(header: Bytes, slice: [UInt8]? = nil,
                                            preferring cpu: UInt32 = MachOHeader.hostCPU) -> FileType {
        guard !header.isEmpty else { return .emptyFile }
        if let machO = MachOHeader.thin(header) { return machO }
        if MachOHeader.isUniversal(header) {
            return MachOHeader.universalType(slice: slice.map { $0[...] } ?? sliceInHeader(header, preferring: cpu))
        }
        if MachOHeader.isJavaClass(header) { return .javaClass }
        if header.starts(with: ShebangLine.magic) { return ShebangLine(header).fileType }
        /// A signature whose first byte isn't the file's is passed over without comparing the rest.
        let first = header[header.startIndex]
        if let signature = signatures.first(where: { signature in
            signature.bytes[0] == first && header.starts(with: signature.bytes)
                && (!signature.binary || !isText(header))
        }) {
            switch signature.type {
            case .zip: return ZipDocument.type(of: header) ?? .zip
            case .binaryPropertyList where DiskImage.isSparseBundle(header): return .sparseBundle
            default: return signature.type
            }
        }
        if header.has(tarMagic.bytes, at: tarMagic.offset) { return .tar }
        if isWindowsExecutable(header) { return .windowsExecutable }
        guard isText(header) else { return DiskImage.rawType(of: header) ?? .data }
        guard isPropertyList(header) else { return .plainText }
        return DiskImage.isSparseBundle(header) ? .sparseBundle : .xmlPropertyList
    }

    /// A type from a file's first bytes, made a disk image's by its end.
    ///
    /// - Parameters:
    ///   - type: The type its first bytes gave (``classify(header:slice:)``).
    ///   - trailer: The file's last ``trailerLength`` bytes, or `nil` when they weren't read.
    /// - Returns: When ``readsTrailer(for:)``, ``FileType/diskImage`` for a trailer that starts with `koly`, or
    ///   ``FileType/encryptedDiskImage`` for data that ends with `cdsaencr`; else `type`.
    static func classify(_ type: FileType, trailer: [UInt8]?) -> FileType {
        guard let trailer, readsTrailer(for: type) else { return type }
        return DiskImage.type(type, trailer: trailer)
    }

    /// A file's type from all its sampled bytes.
    ///
    /// - Parameters:
    ///   - header: The file's first bytes, up to ``headerLength``.
    ///   - slice: A universal binary's slice's first bytes, or `nil` to take them from `header`.
    ///   - trailer: The file's last ``trailerLength`` bytes, or `nil` when they weren't read.
    ///   - cpu: The CPU type whose slice a universal binary is named by, else its first slice's: this Mac's.
    /// - Returns: The type and, for a Mach-O, its file type.
    static func classify<Bytes: ByteSample>(header: Bytes, slice: [UInt8]?, trailer: [UInt8]?,
                                            preferring cpu: UInt32 = MachOHeader.hostCPU) -> FileType {
        classify(classify(header: header, slice: slice, preferring: cpu), trailer: trailer)
    }

    /// Could a file whose first bytes gave this type be a UDIF disk image, so that its end is worth reading?
    ///
    /// - Parameter type: The type its first bytes gave.
    /// - Returns: Whether it's data, a raw disk, or a gzip, bzip2 or xz stream (``DiskImage/trailerHeaders``).
    static func readsTrailer(for type: FileType) -> Bool {
        DiskImage.trailerHeaders.contains(type)
    }

    /// Where a universal binary's slice's header must be read from, when it's past the sampled bytes.
    ///
    /// - Parameters:
    ///   - header: The file's first bytes.
    ///   - cpu: The CPU type whose slice is wanted, else the first: this Mac's.
    /// - Returns: The slice's offset, or `nil` when the bytes aren't a universal header, its offset can't be read at
    ///   (``MachOHeader/sliceOffset(_:preferring:)``), or the sample holds the slice's header already.
    static func sliceOffsetToRead<Bytes: ByteSample>(header: Bytes,
                                                     preferring cpu: UInt32 = MachOHeader.hostCPU) -> UInt64? {
        guard let offset = MachOHeader.sliceOffset(header, preferring: cpu) else { return nil }
        /// The file sets the offset: an end past `UInt64.max` would trap.
        let (end, overflow) = offset.addingReportingOverflow(UInt64(MachOHeader.sliceHeaderLength))
        return overflow || end > UInt64(header.count) ? offset : nil
    }

    /// A universal binary's slice's header, when it starts in the sampled bytes.
    ///
    /// - Parameters:
    ///   - header: The file's first bytes.
    ///   - cpu: The CPU type whose slice is wanted, else the first.
    /// - Returns: Up to ``MachOHeader/sliceHeaderLength`` bytes from the slice's offset, or `nil` when it starts past
    ///   them.
    private static func sliceInHeader<Bytes: ByteSample>(_ header: Bytes,
                                                         preferring cpu: UInt32) -> ArraySlice<UInt8>? {
        guard let offset = MachOHeader.sliceOffset(header, preferring: cpu),
              offset < UInt64(header.count) else { return nil }
        return Array(header.dropFirst(Int(offset)).prefix(MachOHeader.sliceHeaderLength))[...]
    }

    /// Is this a Windows executable: `MZ`, then `PE\0\0` where `e_lfanew` (at `0x3C`) points? An `MZ` whose PE header
    /// is past the sample, or a DOS one without, counts when the bytes aren't text.
    ///
    /// - Parameter header: The file's first bytes.
    /// - Returns: Whether they're a PE or DOS executable's.
    private static func isWindowsExecutable<Bytes: ByteSample>(_ header: Bytes) -> Bool {
        guard header.starts(with: Array("MZ".utf8)) else { return false }
        if let offset = header.uint32(at: 0x3C, bigEndian: false), offset < UInt32(header.count),
           header.has(Array("PE\0\0".utf8), at: Int(offset)) {
            return true
        }
        return !isText(header)
    }

    /// Are these bytes text: valid UTF-8 with no NUL? A sample cut at ``headerLength`` is checked up to the last whole
    /// character, so a character the cut splits doesn't make it data.
    ///
    /// - Parameter bytes: The file's first bytes.
    /// - Returns: Whether they decode as UTF-8 without a NUL.
    static func isText<Bytes: ByteSample>(_ bytes: Bytes) -> Bool {
        var end = bytes.endIndex
        if bytes.count >= headerLength, let lead = bytes.indices.suffix(3).last(where: { bytes[$0] & 0xC0 != 0x80 }) {
            /// The length a lead byte says its character has: 2 for 110xxxxx, 3 for 1110xxxx, 4 for 11110xxx.
            let length = bytes[lead] >= 0xF0 ? 4 : bytes[lead] >= 0xE0 ? 3 : bytes[lead] >= 0xC0 ? 2 : 1
            if lead + length > bytes.endIndex { end = lead }
        }
        var iterator = bytes[bytes.startIndex..<end].makeIterator()
        var decoder = UTF8()
        while true {
            switch decoder.decode(&iterator) {
            case .scalarValue(let scalar) where scalar.value == 0: return false
            case .scalarValue: continue
            case .emptyInput: return true
            case .error: return false
            }
        }
    }

    /// Is this text an XML property list's: after a byte order mark and white space, markup whose sampled bytes hold
    /// `<plist` or `<!DOCTYPE plist`?
    ///
    /// - Parameter text: The file's first bytes, which ``isText(_:)`` passed.
    /// - Returns: Whether it's an XML property list.
    private static func isPropertyList<Bytes: ByteSample>(_ text: Bytes) -> Bool {
        let body = text.starts(with: byteOrderMark) ? text.dropFirst(byteOrderMark.count) : text[...]
        guard body.first(where: { ![0x20, 0x09, 0x0A, 0x0D].contains($0) }) == UInt8(ascii: "<") else { return false }
        return propertyListMarks.contains { text.holds($0) }
    }
}
