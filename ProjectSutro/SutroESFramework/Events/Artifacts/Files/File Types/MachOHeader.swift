//
//  MachOHeader.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation
import MachO


// MARK: - Mach-O headers
/// A Mach-O's type from its header: a thin one's `filetype`, or a universal binary's slice's.
///
/// A thin header (`mach_header`, `mach_header_64`) is in either byte order: its magic says which. A universal header
/// (`fat_header`, then `fat_arch` or `fat_arch_64` entries) is big-endian, though one in little-endian order is read
/// too. Its slice is the one this Mac runs, as the kernel and dyld pick it, else its first: so a universal binary can't
/// hide an `arm64` executable behind a first slice of some other kind. That slice usually starts 16 KB in, past the
/// bytes a file type check samples, so its header is read on its own (``sliceHeaderLength`` bytes at
/// ``sliceOffset(_:preferring:)``).
enum MachOHeader {
    /// The bytes of a slice's header the type needs: a `mach_header_64`, which holds an `ar` archive's `!<arch>\n` too.
    static let sliceHeaderLength = MemoryLayout<mach_header_64>.size
    /// A Java class file starts with `0xCAFEBABE` too, then its minor and major version: a major version of 45 or more
    /// (Java 1.1) where a universal header has its slice count.
    static let javaClassVersion: UInt16 = 45
    /// The `!<arch>\n` an `ar` archive starts with: a static library's slice.
    static let archiveMagic = Array("!<arch>\n".utf8)
    /// The CPU type of the slice this Mac runs.
    static let hostCPU: UInt32 = {
        #if arch(arm64)
        return UInt32(bitPattern: CPU_TYPE_ARM64)
        #else
        return UInt32(bitPattern: CPU_TYPE_X86_64)
        #endif
    }()

    /// The `mach/machine.h` CPU types a slice can be for, without their ABI bits: VAX, 680x0, x86, 98000, HPPA, ARM,
    /// 88000, SPARC, i860 and PowerPC.
    private static let cpuTypes: Set<UInt32> = Set([CPU_TYPE_VAX, CPU_TYPE_MC680x0, CPU_TYPE_X86, CPU_TYPE_MC98000,
                                                    CPU_TYPE_HPPA, CPU_TYPE_ARM, CPU_TYPE_MC88000, CPU_TYPE_SPARC,
                                                    CPU_TYPE_I860, CPU_TYPE_POWERPC].map { UInt32(bitPattern: $0) })
    /// The ABI bits a CPU type can have: none, `CPU_ARCH_ABI64` or `CPU_ARCH_ABI64_32`.
    private static let cpuABIs: Set<UInt32> = [0, UInt32(truncatingIfNeeded: CPU_ARCH_ABI64),
                                               UInt32(truncatingIfNeeded: CPU_ARCH_ABI64_32)]

    /// The names of `mach-o/loader.h`'s file types, by value.
    private static let names: [UInt32: String] = [
        UInt32(MH_OBJECT): "MH_OBJECT", UInt32(MH_EXECUTE): "MH_EXECUTE", UInt32(MH_FVMLIB): "MH_FVMLIB",
        UInt32(MH_CORE): "MH_CORE", UInt32(MH_PRELOAD): "MH_PRELOAD", UInt32(MH_DYLIB): "MH_DYLIB",
        UInt32(MH_DYLINKER): "MH_DYLINKER", UInt32(MH_BUNDLE): "MH_BUNDLE", UInt32(MH_DYLIB_STUB): "MH_DYLIB_STUB",
        UInt32(MH_DSYM): "MH_DSYM", UInt32(MH_KEXT_BUNDLE): "MH_KEXT_BUNDLE", UInt32(MH_FILESET): "MH_FILESET",
        UInt32(MH_GPU_EXECUTE): "MH_GPU_EXECUTE", UInt32(MH_GPU_DYLIB): "MH_GPU_DYLIB",
    ]

    /// The type identifiers of the file types Launch Services declares one for. Every other is a Mach-O binary.
    static let identifiers: [UInt32: String] = [
        UInt32(MH_EXECUTE): "com.apple.mach-o-executable", UInt32(MH_DYLIB): "com.apple.mach-o-dylib",
        UInt32(MH_BUNDLE): "com.apple.mach-o-bundle", UInt32(MH_OBJECT): "com.apple.mach-o-object",
        UInt32(MH_CORE): "com.apple.mach-o-core",
    ]

    /// A file type's `MH_*` name.
    ///
    /// - Parameter fileType: The header's `filetype`.
    /// - Returns: Its name, such as `MH_DYLIB`, or its value in hex (`0x1f`) for one `mach-o/loader.h` doesn't name.
    static func name(of fileType: UInt32) -> String {
        names[fileType] ?? "0x" + String(fileType, radix: 16)
    }

    /// The type of a thin Mach-O, from its header.
    ///
    /// - Parameter bytes: The file's first bytes, or a slice's.
    /// - Returns: The type and its `MH_*` name, a Mach-O binary without a name when the header is cut short before its
    ///   `filetype`, or `nil` when the bytes don't start with a Mach-O magic.
    static func thin<Bytes: ByteSample>(_ bytes: Bytes) -> FileType? {
        let bigEndian: Bool
        switch bytes.uint32(at: 0, bigEndian: false) {
        case UInt32(MH_MAGIC), UInt32(MH_MAGIC_64): bigEndian = false
        case UInt32(MH_CIGAM), UInt32(MH_CIGAM_64): bigEndian = true
        default: return nil
        }
        guard let fileType = bytes.uint32(at: 12, bigEndian: bigEndian) else { return .machOBinary }
        return FileType(identifiers[fileType] ?? FileType.machOBinary.identifier, machOType: name(of: fileType))
    }

    /// Is this a CPU type a slice can be for: one of ``cpuTypes``, with no ABI bits or one of ``cpuABIs``?
    ///
    /// - Parameter cpu: A `fat_arch`'s `cputype`.
    /// - Returns: Whether it's a known CPU type. A Java class's bytes in that place never are: they hold its constant
    ///   pool's count and its first entry's tag, which is never 0, where a CPU type has a 0 byte.
    static func isKnownCPU(_ cpu: UInt32) -> Bool {
        let abi = cpu & UInt32(truncatingIfNeeded: CPU_ARCH_MASK)
        return cpuABIs.contains(abi) && cpuTypes.contains(cpu & ~UInt32(truncatingIfNeeded: CPU_ARCH_MASK))
    }

    /// How a universal header is laid out.
    private struct Layout {
        /// Are its entries `fat_arch_64`, rather than `fat_arch`?
        let wide: Bool
        /// Is it stored most significant byte first?
        let bigEndian: Bool
        /// Its slice count, `nfat_arch`.
        let count: UInt32

        /// The bytes of one entry: a `fat_arch_64`'s 32 or a `fat_arch`'s 20.
        var entryLength: Int { wide ? 32 : 20 }
        /// The most entries the kernel reads: those that fit in a page after the `fat_header`.
        var maximumCount: UInt32 { UInt32((4_096 - 8) / entryLength) }

        /// An entry's `cputype`.
        ///
        /// - Parameters:
        ///   - index: The entry's index.
        ///   - bytes: The file's first bytes.
        /// - Returns: The CPU type, or `nil` when the bytes end before it.
        func cpu<Bytes: ByteSample>(of index: Int, in bytes: Bytes) -> UInt32? {
            bytes.uint32(at: 8 + index * entryLength, bigEndian: bigEndian)
        }

        /// An entry's `offset`, which follows its `cputype` and `cpusubtype`.
        ///
        /// - Parameters:
        ///   - index: The entry's index.
        ///   - bytes: The file's first bytes.
        /// - Returns: The offset, or `nil` when the bytes end before it.
        func offset<Bytes: ByteSample>(of index: Int, in bytes: Bytes) -> UInt64? {
            let start = 8 + index * entryLength + 8
            return wide ? bytes.uint64(at: start, bigEndian: bigEndian)
                : bytes.uint32(at: start, bigEndian: bigEndian).map(UInt64.init)
        }

        /// Does it name a slice the way a universal binary does: a count the kernel accepts, and a known CPU type
        /// first?
        ///
        /// - Parameter bytes: The file's first bytes.
        /// - Returns: Whether its count is from 1 to ``maximumCount`` and its first entry's CPU type is known.
        func namesSlice<Bytes: ByteSample>(in bytes: Bytes) -> Bool {
            (1...maximumCount).contains(count) && cpu(of: 0, in: bytes).map(MachOHeader.isKnownCPU) == true
        }
    }

    /// How a universal header is laid out, when the bytes start with one.
    ///
    /// A big-endian `FAT_MAGIC` is a Java class's magic too. It's a universal header when it names a slice
    /// (``Layout/namesSlice(in:)``), else a Java class when its major version is ``javaClassVersion`` or more, else a
    /// universal header that names none.
    ///
    /// - Parameter bytes: The file's first bytes.
    /// - Returns: Its layout, or `nil` for any other file, a Java class among them.
    private static func universal<Bytes: ByteSample>(_ bytes: Bytes) -> Layout? {
        for bigEndian in [true, false] {
            guard let magic = bytes.uint32(at: 0, bigEndian: bigEndian),
                  magic == UInt32(FAT_MAGIC) || magic == UInt32(FAT_MAGIC_64),
                  let count = bytes.uint32(at: 4, bigEndian: bigEndian) else { continue }
            let layout = Layout(wide: magic == UInt32(FAT_MAGIC_64), bigEndian: bigEndian, count: count)
            guard !layout.wide, bigEndian, !layout.namesSlice(in: bytes) else { return layout }
            /// A class file's major version is the low half of where a universal header has its count.
            return UInt16(truncatingIfNeeded: count) >= javaClassVersion ? nil : layout
        }
        return nil
    }

    /// Is this a universal binary's header?
    ///
    /// - Parameter bytes: The file's first bytes.
    /// - Returns: Whether they start with `FAT_MAGIC` or `FAT_MAGIC_64`, and aren't a Java class's.
    static func isUniversal<Bytes: ByteSample>(_ bytes: Bytes) -> Bool {
        universal(bytes) != nil
    }

    /// Is this a Java class file's header: `0xCAFEBABE`, no slice a universal header would name, and a major version
    /// of ``javaClassVersion`` or more?
    ///
    /// - Parameter bytes: The file's first bytes.
    /// - Returns: Whether they're a class file's.
    static func isJavaClass<Bytes: ByteSample>(_ bytes: Bytes) -> Bool {
        bytes.uint32(at: 0, bigEndian: true) == UInt32(FAT_MAGIC) && bytes.count >= 8 && !isUniversal(bytes)
    }

    /// Where a universal binary's slice starts: the `offset` of the first entry for `cpu`, else of the first entry.
    ///
    /// Only entries in the sampled bytes are looked at, and no more than the kernel reads.
    ///
    /// - Parameters:
    ///   - bytes: The file's first bytes.
    ///   - cpu: The CPU type whose slice is wanted: ``hostCPU``, the one this Mac runs.
    /// - Returns: The offset, or `nil` when the bytes aren't a universal header that names a slice, the entry is cut
    ///   short, or its offset is past any file's end (`Int64.max` or more, which `pread` can't read at).
    static func sliceOffset<Bytes: ByteSample>(_ bytes: Bytes, preferring cpu: UInt32 = hostCPU) -> UInt64? {
        guard let layout = universal(bytes), layout.namesSlice(in: bytes) else { return nil }
        let entries = 0..<Int(min(layout.count, layout.maximumCount))
        let index = entries.first { layout.cpu(of: $0, in: bytes) == cpu } ?? 0
        guard let offset = layout.offset(of: index, in: bytes), offset < UInt64(Int64.max) else { return nil }
        return offset
    }

    /// The type of a universal binary, from its slice's header.
    ///
    /// - Parameter slice: The slice's first bytes, or `nil` when they couldn't be read.
    /// - Returns: The slice's Mach-O type, ``FileType/archive`` for a static library's `ar` archive, or a Mach-O binary
    ///   without a name for a slice that can't be read or is neither.
    static func universalType<Bytes: ByteSample>(slice: Bytes?) -> FileType {
        guard let slice else { return .machOBinary }
        if slice.starts(with: archiveMagic) { return .archive }
        return thin(slice) ?? .machOBinary
    }
}


// MARK: - Reading bytes
/// Bytes sampled from a file: an array, or a slice of one.
protocol ByteSample: RandomAccessCollection where Element == UInt8, Index == Int {}
extension Array: ByteSample where Element == UInt8 {}
extension ArraySlice: ByteSample where Element == UInt8 {}

extension ByteSample {
    /// A 16-bit integer at an offset.
    ///
    /// - Parameters:
    ///   - offset: Its offset from the first byte.
    ///   - bigEndian: Is it stored most significant byte first?
    /// - Returns: The integer, or `nil` when the bytes end before it does.
    func uint16(at offset: Int, bigEndian: Bool) -> UInt16? {
        integer(at: offset, bytes: 2, bigEndian: bigEndian).map { UInt16(truncatingIfNeeded: $0) }
    }

    /// A 32-bit integer at an offset.
    ///
    /// - Parameters:
    ///   - offset: Its offset from the first byte.
    ///   - bigEndian: Is it stored most significant byte first?
    /// - Returns: The integer, or `nil` when the bytes end before it does.
    func uint32(at offset: Int, bigEndian: Bool) -> UInt32? {
        integer(at: offset, bytes: 4, bigEndian: bigEndian).map { UInt32(truncatingIfNeeded: $0) }
    }

    /// A 64-bit integer at an offset.
    ///
    /// - Parameters:
    ///   - offset: Its offset from the first byte.
    ///   - bigEndian: Is it stored most significant byte first?
    /// - Returns: The integer, or `nil` when the bytes end before it does.
    func uint64(at offset: Int, bigEndian: Bool) -> UInt64? {
        integer(at: offset, bytes: 8, bigEndian: bigEndian)
    }

    /// Do the bytes hold these at an offset?
    ///
    /// - Parameters:
    ///   - expected: The bytes to look for.
    ///   - offset: Where they'd start, from the first byte.
    /// - Returns: Whether they're there in full.
    func has(_ expected: [UInt8], at offset: Int) -> Bool {
        guard offset >= 0, count >= offset + expected.count else { return false }
        /// A first byte that differs settles it without the slice.
        guard let first = expected.first, self[startIndex + offset] == first else { return expected.isEmpty }
        return dropFirst(offset).starts(with: expected)
    }

    /// An unsigned integer of up to 8 bytes at an offset.
    ///
    /// - Parameters:
    ///   - offset: Its offset from the first byte.
    ///   - bytes: Its size.
    ///   - bigEndian: Is it stored most significant byte first?
    /// - Returns: The integer, or `nil` when the bytes end before it does.
    private func integer(at offset: Int, bytes size: Int, bigEndian: Bool) -> UInt64? {
        guard offset >= 0, count >= offset + size else { return nil }
        let start = startIndex + offset
        var value: UInt64 = 0
        for index in 0..<size {
            value = value << 8 | UInt64(self[start + (bigEndian ? index : size - 1 - index)])
        }
        return value
    }
}
