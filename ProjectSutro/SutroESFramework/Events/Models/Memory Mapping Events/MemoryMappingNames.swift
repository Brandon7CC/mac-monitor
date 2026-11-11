//
//  MemoryMappingNames.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation


// MARK: - Memory mapping names
/// The names of the bits set in an mmap's `protection`, `max_protection` or `flags`, from `<sys/mman.h>`.
///
/// Each table lists one name per bit, in bit order, with literal values (the header's macros import as `Int32`, and
/// tests check each one against them). A bit no table names is left out: the raw integer is always exported beside
/// the names, so nothing is lost.
public struct MemoryMappingNames {
    /// The bits the table names, in bit order.
    let bits: [(bit: UInt32, name: String)]
    /// The name of a value with no bits set, or `nil` to name none.
    let zero: String?

    /// `protection` and `max_protection`: `PROT_READ`, `PROT_WRITE` and `PROT_EXEC`, and `PROT_NONE` for 0.
    ///
    /// `max_protection` is a `vm_prot_t` that the kernel seeds and each MAC policy narrows. Its low three bits are
    /// `VM_PROT_READ`, `VM_PROT_WRITE` and `VM_PROT_EXECUTE`, the same bits as `PROT_*`, so it's named with `PROT_*`
    /// too. Its other `VM_PROT_*` bits are left out.
    public static let protection = MemoryMappingNames(zero: "PROT_NONE", bits: [
        (0x0000_0001, "PROT_READ"),
        (0x0000_0002, "PROT_WRITE"),
        (0x0000_0004, "PROT_EXEC"),
    ])

    /// `flags`: the `MAP_*` flags. `MAP_FILE` is 0, the absence of `MAP_ANON`, so it's never named, and flags of 0
    /// have no names. Aliases have one name: `MAP_PRIVATE` (not `MAP_COPY`) and `MAP_ANON` (not `MAP_ANONYMOUS`).
    public static let flags = MemoryMappingNames(zero: nil, bits: [
        (0x0000_0001, "MAP_SHARED"),
        (0x0000_0002, "MAP_PRIVATE"),
        (0x0000_0010, "MAP_FIXED"),
        (0x0000_0020, "MAP_RENAME"),
        (0x0000_0040, "MAP_NORESERVE"),
        (0x0000_0080, "MAP_RESERVED0080"),
        (0x0000_0100, "MAP_NOEXTEND"),
        (0x0000_0200, "MAP_HASSEMAPHORE"),
        (0x0000_0400, "MAP_NOCACHE"),
        (0x0000_0800, "MAP_JIT"),
        (0x0000_1000, "MAP_ANON"),
        (0x0000_2000, "MAP_RESILIENT_CODESIGN"),
        (0x0000_4000, "MAP_RESILIENT_MEDIA"),
        (0x0000_8000, "MAP_32BIT"),
        (0x0002_0000, "MAP_TRANSLATED_ALLOW_EXECUTE"),
        (0x0004_0000, "MAP_UNIX03"),
        (0x0008_0000, "MAP_TPRO"),
    ])

    /// A table of a bitmask's names.
    ///
    /// - Parameters:
    ///   - zero: The name of a value with no bits set, or `nil` to name none.
    ///   - bits: The bits and their names, in bit order.
    private init(zero: String?, bits: [(bit: UInt32, name: String)]) {
        self.zero = zero
        self.bits = bits
    }

    /// The names of the bits a value has.
    ///
    /// - Parameter value: Endpoint Security's `int32_t`, read by bit pattern, so bit 31 (a negative value) is a bit
    ///   like any other.
    /// - Returns: The names, in bit order: the zero name for a value of 0, and none for bits the table doesn't name.
    public func names(_ value: Int32) -> [String] {
        let bits = UInt32(truncatingIfNeeded: value)
        if bits == 0, let zero { return [zero] }
        return self.bits.filter { bits & $0.bit != 0 }.map(\.name)
    }

    /// A value as the Event Facts show it: its names joined by " | ", then the value: "PROT_READ | PROT_EXEC (5)".
    ///
    /// - Parameter value: Endpoint Security's `int32_t`.
    /// - Returns: The label, or only the value when it has no names.
    public func label(_ value: Int32) -> String {
        let names = self.names(value)
        return names.isEmpty ? "\(value)" : "\(names.joined(separator: " | ")) (\(value))"
    }
}


// MARK: - Notation
extension MemoryMappingNames {
    /// A protection in `vmmap`'s notation: `r`, `w` and `x` for `PROT_READ`, `PROT_WRITE` and `PROT_EXEC`, and `-` for
    /// each that's unset, such as "r-x". Other bits are left out, as ``names(_:)`` leaves them out.
    ///
    /// - Parameter protection: `protection` or `max_protection`, Endpoint Security's `int32_t`.
    /// - Returns: Three characters, "---" for `PROT_NONE`.
    public static func permissions(_ protection: Int32) -> String {
        let bits = UInt32(truncatingIfNeeded: protection)
        return [(0x1, "r"), (0x2, "w"), (0x4, "x")].map { bits & $0.0 != 0 ? $0.1 : "-" }.joined()
    }

    /// A value's 32 bits as eight hex digits, as the Event Facts show code signing flags: "0x00040012".
    ///
    /// - Parameter value: Endpoint Security's `int32_t`, read by bit pattern.
    /// - Returns: The hex.
    public static func hex(_ value: Int32) -> String {
        String(format: "0x%08X", UInt32(truncatingIfNeeded: value))
    }
}


// MARK: - Callouts
/// What an mmap's requested protection is worth pointing out: asking to map a file executable, or writable and
/// executable at once.
///
/// Endpoint Security reports `protection` from the MAC check before the mapping is made, so it's what the process
/// asked for. The kernel's W^X policy then strips execute from a writable and executable request, or fails it, on
/// Apple silicon (and on Intel under code signing enforcement): a file can't take the `MAP_JIT` exception, which
/// needs `MAP_ANON`. Asking is the signal.
public enum MemoryMappingCallout: Equatable, Sendable {
    /// `PROT_EXEC` without `PROT_WRITE`.
    case executable
    /// `PROT_WRITE` and `PROT_EXEC` together.
    case writableAndExecutable

    /// The callout a protection earns.
    ///
    /// - Parameter protection: `protection`, Endpoint Security's `int32_t`. `max_protection` only bounds what an
    ///   `mprotect` may later ask for, so it earns none.
    /// - Returns: The callout, or `nil` for a mapping that isn't executable.
    public init?(protection: Int32) {
        switch (protection & PROT_WRITE != 0, protection & PROT_EXEC != 0) {
        case (true, true): self = .writableAndExecutable
        case (false, true): self = .executable
        default: return nil
        }
    }
}
