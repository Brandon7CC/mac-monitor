//
//  FileMode.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation


// MARK: - File mode
/// A file's permission bits as `ls -l` and `stat -f %Sp` show them, from `<sys/stat.h>`: the 12 bits `chmod` sets,
/// as octal ("0644") and as symbols ("rw-r--r--").
///
/// The bits are literal values here (`<sys/stat.h>`'s macros import with different integer types, and tests check
/// each one against them).
public struct FileMode: Equatable, Sendable {
    /// `S_ISUID`: run as the file's owner. A directory keeps the bit but nothing reads it.
    static let setuid: UInt16 = 0o4000
    /// `S_ISGID`: run as the file's group. On a directory it changes nothing, since a new file on macOS always takes
    /// its directory's group.
    static let setgid: UInt16 = 0o2000
    /// `S_ISVTX`: the sticky bit, which on a directory lets only a file's owner remove or rename it.
    static let sticky: UInt16 = 0o1000
    /// `S_IXUSR | S_IXGRP | S_IXOTH`: execute, or search on a directory, for owner, group and others.
    static let execute: UInt16 = 0o0111
    /// `S_IWOTH`: write for others, anyone on the Mac.
    static let worldWrite: UInt16 = 0o0002
    /// `S_IFMT`: the file type's bits, which a stat's `st_mode` has and `chmod`'s mode doesn't.
    static let typeMask: UInt32 = 0o170000
    /// `S_IFDIR`: the file type of a directory.
    static let directory: UInt32 = 0o040000

    /// The permission bits: `mode & 07777`.
    public let permissions: UInt16
    /// Whether the mode's file type is a directory. Only a stat's `st_mode` has a type, so a setmode's `mode` is never
    /// a directory's.
    public let isDirectory: Bool

    /// A mode from its integer: a setmode's `mode`, or a stat's `st_mode`.
    ///
    /// - Parameter mode: The mode, read by bit pattern, so a negative value doesn't trap. Bits past the type's are
    ///   left out.
    public init(_ mode: some BinaryInteger) {
        let bits = UInt32(truncatingIfNeeded: mode)
        permissions = UInt16(bits & 0o7777)
        isDirectory = bits & Self.typeMask == Self.directory
    }

    /// The mode a file had, from its stat.
    ///
    /// - Parameter statMode: The stat's `st_mode`. Every file has a type, so an `st_mode` of 0 means there was no stat,
    ///   as in a trace that didn't carry one.
    /// - Returns: The mode, or `nil` for an `st_mode` of 0.
    public init?(statMode: some BinaryInteger) {
        guard statMode != 0 else { return nil }
        self.init(statMode)
    }

    /// The permission bits as four octal digits, as `chmod` takes them: "0644", "4755".
    public var octal: String {
        let digits = String(permissions, radix: 8)
        return String(repeating: "0", count: max(0, 4 - digits.count)) + digits
    }

    /// The permission bits as `ls -l` shows them, without the file type: "rw-r--r--". Setuid and setgid show in the
    /// owner's and group's execute place as `s`, or `S` without execute, and the sticky bit in others' as `t` or `T`.
    public var symbolic: String {
        [(6, Self.setuid, "s"), (3, Self.setgid, "s"), (0, Self.sticky, "t")].map { shift, special, letter in
            let rwx = permissions >> shift
            let executes = rwx & 1 != 0
            let execute = permissions & special == 0
                ? (executes ? "x" : "-") : (executes ? letter : letter.uppercased())
            return (rwx & 4 != 0 ? "r" : "-") + (rwx & 2 != 0 ? "w" : "-") + execute
        }.joined()
    }

    /// The mode as the Event Facts show it: octal, then symbols, such as "0644 rw-r--r--".
    public var label: String {
        "\(octal) \(symbolic)"
    }
}


// MARK: - Callouts
/// What a setmode added that's worth pointing out: execute (the download, `chmod +x`, run pattern), setuid, setgid,
/// or write for everyone.
///
/// Endpoint Security reports the target's stat from before the change, so its `st_mode` is the previous mode and the
/// event's `mode` the new one. That stat also says whether the target is a directory, and a directory earns only
/// `worldWritable`, and not that when it's sticky.
public enum FileModeCallout: Hashable, Sendable, CaseIterable {
    /// An execute bit the file didn't have. A directory's execute bits are search bits, so a directory earns none.
    case madeExecutable
    /// `S_ISUID` the file didn't have. A directory ignores setuid, so a directory earns none.
    case setuidAdded
    /// `S_ISGID` the file didn't have. A directory's setgid changes nothing on macOS, so a directory earns none.
    case setgidAdded
    /// `S_IWOTH` the file didn't have. A sticky directory, as `/tmp`'s 1777 is, lets only a file's owner remove or
    /// rename it, so a directory whose new mode is sticky earns none.
    case worldWritable

    /// What a change of mode added, in the order of the cases.
    ///
    /// - Parameters:
    ///   - mode: The new mode.
    ///   - previous: The mode before the change, or `nil` when it isn't known. With no previous mode, every bit the new
    ///     mode sets counts as added, since none can be ruled out, and the target counts as a file, not a directory.
    /// - Returns: The callouts, none when nothing worth pointing out was added.
    public static func added(to mode: FileMode, from previous: FileMode?) -> [FileModeCallout] {
        let added = mode.permissions & ~(previous?.permissions ?? 0)
        let isDirectory = previous?.isDirectory ?? false
        let isStickyDirectory = isDirectory && mode.permissions & FileMode.sticky != 0
        return allCases.filter { callout in
            switch callout {
            case .madeExecutable: return !isDirectory && added & FileMode.execute != 0
            case .setuidAdded: return !isDirectory && added & FileMode.setuid != 0
            case .setgidAdded: return !isDirectory && added & FileMode.setgid != 0
            case .worldWritable: return !isStickyDirectory && added & FileMode.worldWrite != 0
            }
        }
    }
}

extension FileModeCallout {
    /// The callout's name in telemetry, as `event.setmode.mode_added` lists it: `executable`, `setuid`, `setgid` or
    /// `world_writable`.
    public var telemetryName: String {
        switch self {
        case .madeExecutable: return "executable"
        case .setuidAdded: return "setuid"
        case .setgidAdded: return "setgid"
        case .worldWritable: return "world_writable"
        }
    }
}
