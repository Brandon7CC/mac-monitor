//
//  FileTypeSamples.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
import MachO
@testable import SutroESFramework


// MARK: - Synthetic file contents
/// The first bytes of files of each kind a file type check tells apart, made up byte by byte: Mach-O and universal
/// headers, archives' and disk images' signatures.
enum FileTypeSamples {
    /// A 32-bit word.
    ///
    /// - Parameters:
    ///   - value: The word.
    ///   - bigEndian: Write it most significant byte first?
    /// - Returns: Its 4 bytes.
    static func word(_ value: UInt32, bigEndian: Bool = false) -> [UInt8] {
        let ordered = bigEndian ? value.bigEndian : value.littleEndian
        return withUnsafeBytes(of: ordered) { Array($0) }
    }

    /// A 64-bit word.
    ///
    /// - Parameters:
    ///   - value: The word.
    ///   - bigEndian: Write it most significant byte first?
    /// - Returns: Its 8 bytes.
    static func doubleWord(_ value: UInt64, bigEndian: Bool = false) -> [UInt8] {
        let ordered = bigEndian ? value.bigEndian : value.littleEndian
        return withUnsafeBytes(of: ordered) { Array($0) }
    }

    /// A thin Mach-O's header, padded to a `mach_header_64`'s size.
    ///
    /// - Parameters:
    ///   - fileType: Its `filetype`, such as `MH_DYLIB`.
    ///   - wide: A 64-bit header (`MH_MAGIC_64`) rather than a 32-bit one?
    ///   - bigEndian: Stored most significant byte first, as a PowerPC binary is?
    /// - Returns: The header's bytes.
    static func machO(_ fileType: Int32, wide: Bool = true, bigEndian: Bool = false) -> [UInt8] {
        let magic = wide ? UInt32(MH_MAGIC_64) : UInt32(MH_MAGIC)
        let header = word(magic, bigEndian: bigEndian) + word(UInt32(bitPattern: CPU_TYPE_ARM64), bigEndian: bigEndian)
            + word(0, bigEndian: bigEndian) + word(UInt32(fileType), bigEndian: bigEndian)
        return header + [UInt8](repeating: 0, count: MachOHeader.sliceHeaderLength - header.count)
    }

    /// A universal header with one slice.
    ///
    /// - Parameters:
    ///   - offset: The slice's offset.
    ///   - wide: `FAT_MAGIC_64` and a `fat_arch_64`, rather than `FAT_MAGIC` and a `fat_arch`?
    ///   - count: The slice count it states.
    ///   - bigEndian: Stored most significant byte first, as every universal header is?
    /// - Returns: The header's bytes.
    static func universal(sliceAt offset: UInt64, wide: Bool = false, count: UInt32 = 1,
                          bigEndian: Bool = true) -> [UInt8] {
        let magic = wide ? UInt32(FAT_MAGIC_64) : UInt32(FAT_MAGIC)
        let type = word(UInt32(bitPattern: CPU_TYPE_ARM64), bigEndian: bigEndian) + word(0, bigEndian: bigEndian)
        let place = wide ? doubleWord(offset, bigEndian: bigEndian) + doubleWord(4_096, bigEndian: bigEndian)
            : word(UInt32(offset), bigEndian: bigEndian) + word(4_096, bigEndian: bigEndian)
        return word(magic, bigEndian: bigEndian) + word(count, bigEndian: bigEndian) + type + place
            + word(14, bigEndian: bigEndian) + (wide ? word(0, bigEndian: bigEndian) : [])
    }

    /// A universal header with an entry for each slice, all `cpusubtype` 0 and 4 KB long.
    ///
    /// - Parameters:
    ///   - slices: Each slice's `cputype` and offset, in order.
    ///   - wide: `FAT_MAGIC_64` and `fat_arch_64` entries, rather than `FAT_MAGIC` and `fat_arch` ones?
    ///   - count: The slice count it states, the entries' by default.
    /// - Returns: The header's bytes, big-endian.
    static func universal(slices: [(cpu: UInt32, offset: UInt64)], wide: Bool = false,
                          count: UInt32? = nil) -> [UInt8] {
        let magic = wide ? UInt32(FAT_MAGIC_64) : UInt32(FAT_MAGIC)
        let entries = slices.flatMap { slice in
            let place = wide ? doubleWord(slice.offset, bigEndian: true) + doubleWord(4_096, bigEndian: true)
                : word(UInt32(truncatingIfNeeded: slice.offset), bigEndian: true) + word(4_096, bigEndian: true)
            return word(slice.cpu, bigEndian: true) + word(0, bigEndian: true) + place + word(14, bigEndian: true)
                + (wide ? word(0, bigEndian: true) : [])
        }
        return word(magic, bigEndian: true) + word(count ?? UInt32(slices.count), bigEndian: true) + entries
    }

    /// A universal binary whose first slice starts inside its first bytes.
    ///
    /// - Parameters:
    ///   - slice: The slice's first bytes.
    ///   - offset: Where it starts.
    /// - Returns: The file's first bytes.
    static func universal(with slice: [UInt8], at offset: Int = 64) -> [UInt8] {
        let header = universal(sliceAt: UInt64(offset))
        return header + [UInt8](repeating: 0, count: offset - header.count) + slice
    }

    /// Bytes that start with these, then zeros.
    ///
    /// - Parameters:
    ///   - signature: The first bytes.
    ///   - length: The bytes in all.
    /// - Returns: The bytes.
    static func starting(with signature: [UInt8], length: Int = 64) -> [UInt8] {
        signature + [UInt8](repeating: 0, count: max(0, length - signature.count))
    }

    /// Text's bytes.
    ///
    /// - Parameter text: The text.
    /// - Returns: Its UTF-8.
    static func text(_ text: String) -> [UInt8] { Array(text.utf8) }

    /// A UDIF image's trailer: `koly`, then the rest of its 512 bytes.
    static let diskImageTrailer = starting(with: text("koly") + word(4, bigEndian: true),
                                           length: FileTypeClassifier.trailerLength)

    /// A POSIX tar archive's first header: a file name, then `ustar` 257 bytes in.
    static let tarHeader: [UInt8] = {
        var header = starting(with: text("notes.txt"), length: 512)
        header.replaceSubrange(257..<263, with: text("ustar\0"))
        return header
    }()
}


// MARK: - Files to read
extension XCTestCase {
    /// A new temporary directory's path with no symbolic link in it, as Endpoint Security names files:
    /// `/private/var/folders/...`, not `/var/folders/...`. A file type read refuses a path with a link on it.
    ///
    /// - Returns: The directory's resolved path.
    /// - Throws: The error making it, or the `POSIXError` of `realpath`.
    func resolvedTemporaryDirectory() throws -> String {
        let directory = try makeTemporaryDirectory().path
        guard let resolved = realpath(directory, nil) else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    /// A file in a new temporary directory, by a path with no symbolic link in it.
    ///
    /// - Parameters:
    ///   - bytes: Its contents.
    ///   - name: Its name.
    ///   - mode: Its permissions.
    /// - Returns: Its path.
    /// - Throws: The error writing it.
    func temporaryFile(bytes: [UInt8], named name: String = "sample", mode: mode_t = 0o644) throws -> String {
        let path = try resolvedTemporaryDirectory().appendingPathComponent(name)
        try Data(bytes).write(to: URL(fileURLWithPath: path))
        chmod(path, mode)
        return path
    }

    /// A copy of a file in a new temporary directory, by a path with no symbolic link in it.
    ///
    /// - Parameters:
    ///   - source: The file to copy. A symbolic link is followed, as a framework's executable is one.
    ///   - name: The copy's name, the source's by default.
    /// - Returns: The copy's path.
    /// - Throws: The error copying it.
    func temporaryCopy(of source: String, named name: String? = nil) throws -> String {
        let path = try resolvedTemporaryDirectory().appendingPathComponent(name ?? source.lastPathComponent)
        let file = URL(fileURLWithPath: source).resolvingSymlinksInPath().path
        try FileManager.default.copyItem(atPath: file, toPath: path)
        return path
    }

    /// A file's `stat`, as Endpoint Security reports the file: of a symbolic link itself with `followingLinks` off.
    ///
    /// - Parameters:
    ///   - path: The file's path.
    ///   - followingLinks: Follow a symbolic link at the path?
    /// - Returns: The stat.
    /// - Throws: The `POSIXError` of `stat` or `lstat`.
    func fileStat(_ path: String, followingLinks: Bool = true) throws -> stat {
        var info = stat()
        guard (followingLinks ? stat(path, &info) : lstat(path, &info)) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        return info
    }

    /// The reader for this test process's own user and group.
    var currentReader: FileReader { FileReader(uid: getuid(), gid: getgid()) }
}
