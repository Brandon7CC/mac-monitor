//
//  MemoryMappingNamesTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
import Darwin
@testable import SutroESFramework


// MARK: - mmap protection and flag names
/// Pins ``MemoryMappingNames``: each table's literals equal the SDK's `<sys/mman.h>` constants, names come out in bit
/// order with one name per bit, a protection of 0 is `PROT_NONE`, flags of 0 (`MAP_FILE`) have no names, and bits the
/// header doesn't name (bit 31 included) are dropped without trapping.
final class MemoryMappingNamesTests: XCTestCase {
    /// `<sys/mman.h>`'s protections, as Swift imports them, in bit order.
    private static let sdkProtections: [(value: Int32, name: String)] = [
        (PROT_READ, "PROT_READ"), (PROT_WRITE, "PROT_WRITE"), (PROT_EXEC, "PROT_EXEC"),
    ]

    /// `<sys/mman.h>`'s flags, as Swift imports them, in bit order, without the aliases or `MAP_FILE`.
    private static let sdkFlags: [(value: Int32, name: String)] = [
        (MAP_SHARED, "MAP_SHARED"), (MAP_PRIVATE, "MAP_PRIVATE"), (MAP_FIXED, "MAP_FIXED"),
        (MAP_RENAME, "MAP_RENAME"), (MAP_NORESERVE, "MAP_NORESERVE"), (MAP_RESERVED0080, "MAP_RESERVED0080"),
        (MAP_NOEXTEND, "MAP_NOEXTEND"), (MAP_HASSEMAPHORE, "MAP_HASSEMAPHORE"), (MAP_NOCACHE, "MAP_NOCACHE"),
        (MAP_JIT, "MAP_JIT"), (MAP_ANON, "MAP_ANON"), (MAP_RESILIENT_CODESIGN, "MAP_RESILIENT_CODESIGN"),
        (MAP_RESILIENT_MEDIA, "MAP_RESILIENT_MEDIA"), (MAP_32BIT, "MAP_32BIT"),
        (MAP_TRANSLATED_ALLOW_EXECUTE, "MAP_TRANSLATED_ALLOW_EXECUTE"), (MAP_UNIX03, "MAP_UNIX03"),
        (MAP_TPRO, "MAP_TPRO"),
    ]

    /// The protection table.
    private let protection = MemoryMappingNames.protection
    /// The flag table.
    private let flags = MemoryMappingNames.flags

    // MARK: Tables

    /// Assert that a table lists exactly the SDK's constants, by name and value, each a single bit, in bit order.
    ///
    /// - Parameters:
    ///   - table: The table.
    ///   - sdk: The SDK's constants, in bit order.
    ///   - line: The caller's line.
    private func assertTable(_ table: MemoryMappingNames, equals sdk: [(value: Int32, name: String)],
                             line: UInt = #line) {
        XCTAssertEqual(table.bits.map(\.name), sdk.map(\.name), line: line)
        XCTAssertEqual(table.bits.map(\.bit), sdk.map { UInt32($0.value) }, line: line)
        XCTAssertTrue(table.bits.allSatisfy { $0.bit.nonzeroBitCount == 1 }, line: line)
        XCTAssertEqual(table.bits.map(\.bit), table.bits.map(\.bit).sorted(), line: line)
    }

    /// The protection table is `<sys/mman.h>`'s `PROT_*`.
    func testProtectionTableMatchesSDK() {
        assertTable(protection, equals: Self.sdkProtections)
        XCTAssertEqual(PROT_NONE, 0)
    }

    /// The flag table is `<sys/mman.h>`'s `MAP_*`, one name per bit.
    func testFlagTableMatchesSDK() {
        assertTable(flags, equals: Self.sdkFlags)
    }

    /// `max_protection` is a `vm_prot_t`: its low three bits are `VM_PROT_*`'s, so the `PROT_*` names fit it.
    func testProtectionBitsAreVMProtectionBits() {
        XCTAssertEqual([VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE], Self.sdkProtections.map(\.value))
    }

    // MARK: Protection

    /// A protection of 0 is `PROT_NONE`, and the others name their bits in bit order.
    func testProtectionNames() {
        XCTAssertEqual(protection.names(0), ["PROT_NONE"])
        XCTAssertEqual(protection.names(PROT_READ), ["PROT_READ"])
        XCTAssertEqual(protection.names(PROT_EXEC | PROT_READ), ["PROT_READ", "PROT_EXEC"])
        XCTAssertEqual(protection.names(7), ["PROT_READ", "PROT_WRITE", "PROT_EXEC"])
    }

    /// Bits `<sys/mman.h>` doesn't name, such as `VM_PROT_STRIP_READ` in a `max_protection`, are dropped. Only 0 is
    /// `PROT_NONE`: a protection with only unnamed bits has no names.
    func testProtectionDropsUnknownBits() {
        XCTAssertEqual(protection.names(0x80 | PROT_READ), ["PROT_READ"])
        XCTAssertEqual(protection.names(0x8), [])
        XCTAssertEqual(protection.names(VM_PROT_NO_CHANGE | 7), ["PROT_READ", "PROT_WRITE", "PROT_EXEC"])
    }

    /// Bit 31, a negative `int32_t`, is read by bit pattern without trapping.
    func testProtectionBit31DoesNotTrap() {
        XCTAssertEqual(protection.names(Int32.min), [])
        XCTAssertEqual(protection.names(-1), ["PROT_READ", "PROT_WRITE", "PROT_EXEC"])
    }

    // MARK: Flags

    /// Flags of 0 (`MAP_FILE`, a file mapping's default) have no names, and `MAP_FILE` is never named.
    func testZeroFlagsHaveNoNames() {
        XCTAssertEqual(MAP_FILE, 0)
        XCTAssertEqual(flags.names(MAP_FILE), [])
        XCTAssertFalse(flags.names(-1).contains("MAP_FILE"))
    }

    /// Mixed flags name their bits in bit order, whatever order they're OR-ed in.
    func testFlagNamesAreInBitOrder() {
        XCTAssertEqual(flags.names(MAP_FIXED | MAP_PRIVATE), ["MAP_PRIVATE", "MAP_FIXED"])
        XCTAssertEqual(flags.names(MAP_JIT | MAP_ANON | MAP_PRIVATE), ["MAP_PRIVATE", "MAP_JIT", "MAP_ANON"])
        XCTAssertEqual(flags.names(MAP_UNIX03 | MAP_SHARED), ["MAP_SHARED", "MAP_UNIX03"])
    }

    /// Aliases have one name: `MAP_COPY` is `MAP_PRIVATE` and `MAP_ANONYMOUS` is `MAP_ANON`.
    func testAliasesAreNamedOnce() {
        XCTAssertEqual(flags.names(MAP_COPY), ["MAP_PRIVATE"])
        XCTAssertEqual(flags.names(MAP_ANONYMOUS), ["MAP_ANON"])
        let every = Self.sdkFlags.reduce(Int32(0)) { $0 | $1.value }
        XCTAssertEqual(flags.names(every | MAP_COPY | MAP_ANONYMOUS), Self.sdkFlags.map(\.name))
    }

    /// Bits `<sys/mman.h>` doesn't name are dropped: the raw `flags` keeps them.
    func testFlagsDropUnknownBits() {
        for bit: Int32 in [0x4, 0x8, 0x1_0000, 0x10_0000, 0x4000_0000] {
            XCTAssertEqual(flags.names(bit), [], String(bit, radix: 16))
        }
        XCTAssertEqual(flags.names(0x1_0000 | MAP_PRIVATE), ["MAP_PRIVATE"])
    }

    /// Bit 31, a negative `int32_t`, is read by bit pattern without trapping, and every bit set names each flag once.
    func testFlagsBit31DoesNotTrap() {
        XCTAssertEqual(flags.names(Int32.min), [])
        XCTAssertEqual(flags.names(Int32.min | MAP_SHARED), ["MAP_SHARED"])
        XCTAssertEqual(flags.names(-1), Self.sdkFlags.map(\.name))
    }

    // MARK: Labels

    /// The Event Facts show the names beside the value, or only the value when it has none.
    func testLabels() {
        XCTAssertEqual(protection.label(PROT_READ | PROT_EXEC), "PROT_READ | PROT_EXEC (5)")
        XCTAssertEqual(protection.label(0), "PROT_NONE (0)")
        XCTAssertEqual(flags.label(MAP_PRIVATE | MAP_FIXED), "MAP_PRIVATE | MAP_FIXED (18)")
        XCTAssertEqual(flags.label(0), "0")
        XCTAssertEqual(flags.label(0x1_0000), "65536")
    }

    // MARK: Notation

    /// Protections read as `vmmap` writes them, and other bits are left out.
    func testPermissions() {
        XCTAssertEqual(MemoryMappingNames.permissions(0), "---")
        XCTAssertEqual(MemoryMappingNames.permissions(PROT_READ), "r--")
        XCTAssertEqual(MemoryMappingNames.permissions(PROT_READ | PROT_WRITE), "rw-")
        XCTAssertEqual(MemoryMappingNames.permissions(PROT_READ | PROT_EXEC), "r-x")
        XCTAssertEqual(MemoryMappingNames.permissions(PROT_READ | PROT_WRITE | PROT_EXEC), "rwx")
        XCTAssertEqual(MemoryMappingNames.permissions(Int32.min | 0x10 | PROT_EXEC), "--x")
    }

    /// Flags show as eight hex digits by bit pattern, a negative value included.
    func testHex() {
        XCTAssertEqual(MemoryMappingNames.hex(MAP_PRIVATE | MAP_FIXED | MAP_UNIX03), "0x00040012")
        XCTAssertEqual(MemoryMappingNames.hex(0), "0x00000000")
        XCTAssertEqual(MemoryMappingNames.hex(-1), "0xFFFFFFFF")
    }

    // MARK: Callouts

    /// Only an executable protection earns a callout, and writable with executable earns the stronger one, read or not.
    func testCallouts() {
        XCTAssertNil(MemoryMappingCallout(protection: 0))
        XCTAssertNil(MemoryMappingCallout(protection: PROT_READ))
        XCTAssertNil(MemoryMappingCallout(protection: PROT_READ | PROT_WRITE))
        XCTAssertEqual(MemoryMappingCallout(protection: PROT_EXEC), .executable)
        XCTAssertEqual(MemoryMappingCallout(protection: PROT_READ | PROT_EXEC), .executable)
        XCTAssertEqual(MemoryMappingCallout(protection: PROT_WRITE | PROT_EXEC), .writableAndExecutable)
        XCTAssertEqual(MemoryMappingCallout(protection: PROT_READ | PROT_WRITE | PROT_EXEC), .writableAndExecutable)
        XCTAssertEqual(MemoryMappingCallout(protection: Int32.min | PROT_EXEC), .executable)
    }
}
