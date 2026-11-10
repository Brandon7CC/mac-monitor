//
//  FileModeTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
import Darwin
@testable import SutroESFramework


// MARK: - File modes and setmode callouts
/// Pins ``FileMode`` and ``FileModeCallout``: the literals equal the SDK's `<sys/stat.h>` constants, modes read as
/// `chmod`'s octal and `ls -l`'s symbols (setuid, setgid and sticky as `s`/`S`, `s`/`S` and `t`/`T`), a stat's file
/// type is kept apart from its permissions, and a change of mode calls out only what it added.
final class FileModeTests: XCTestCase {
    /// A mode from octal.
    ///
    /// - Parameter octal: The mode, as `chmod` takes it.
    /// - Returns: The mode.
    private func mode(_ octal: Int) -> FileMode { FileMode(octal) }

    /// The callouts a change of mode earns.
    ///
    /// - Parameters:
    ///   - previous: The stat's `st_mode` before the change, or `nil` for no stat.
    ///   - new: The setmode's `mode`.
    /// - Returns: The callouts.
    private func added(from previous: Int?, to new: Int) -> [FileModeCallout] {
        FileModeCallout.added(to: FileMode(new), from: previous.flatMap { FileMode(statMode: $0) })
    }

    // MARK: Constants

    /// The literals are `<sys/stat.h>`'s.
    func testConstantsMatchSDK() {
        XCTAssertEqual(FileMode.setuid, UInt16(S_ISUID))
        XCTAssertEqual(FileMode.setgid, UInt16(S_ISGID))
        XCTAssertEqual(FileMode.sticky, UInt16(S_ISVTX))
        XCTAssertEqual(FileMode.execute, UInt16(S_IXUSR | S_IXGRP | S_IXOTH))
        XCTAssertEqual(FileMode.worldWrite, UInt16(S_IWOTH))
        XCTAssertEqual(FileMode.typeMask, UInt32(S_IFMT))
        XCTAssertEqual(FileMode.directory, UInt32(S_IFDIR))
    }

    // MARK: Notation

    /// The permission bits read as four octal digits, padded, with the special bits in the first.
    func testOctal() {
        XCTAssertEqual(mode(0o644).octal, "0644")
        XCTAssertEqual(mode(0o755).octal, "0755")
        XCTAssertEqual(mode(0).octal, "0000")
        XCTAssertEqual(mode(0o7).octal, "0007")
        XCTAssertEqual(mode(0o4755).octal, "4755")
        XCTAssertEqual(mode(0o7777).octal, "7777")
    }

    /// The permission bits read as `ls -l` writes them.
    func testSymbolic() {
        XCTAssertEqual(mode(0o644).symbolic, "rw-r--r--")
        XCTAssertEqual(mode(0o755).symbolic, "rwxr-xr-x")
        XCTAssertEqual(mode(0).symbolic, "---------")
        XCTAssertEqual(mode(0o777).symbolic, "rwxrwxrwx")
        XCTAssertEqual(mode(0o640).symbolic, "rw-r-----")
    }

    /// Setuid, setgid and sticky take the execute places, lowercase with execute and uppercase without.
    func testSymbolicSpecialBits() {
        XCTAssertEqual(mode(0o4755).symbolic, "rwsr-xr-x")
        XCTAssertEqual(mode(0o4644).symbolic, "rwSr--r--")
        XCTAssertEqual(mode(0o2755).symbolic, "rwxr-sr-x")
        XCTAssertEqual(mode(0o2745).symbolic, "rwxr-Sr-x")
        XCTAssertEqual(mode(0o1777).symbolic, "rwxrwxrwt")
        XCTAssertEqual(mode(0o1776).symbolic, "rwxrwxrwT")
        XCTAssertEqual(mode(0o7000).symbolic, "--S--S--T")
        XCTAssertEqual(mode(0o7777).symbolic, "rwsrwsrwt")
    }

    /// The Event Facts show octal, then symbols.
    func testLabel() {
        XCTAssertEqual(mode(0o644).label, "0644 rw-r--r--")
        XCTAssertEqual(mode(0o4755).label, "4755 rwsr-xr-x")
    }

    // MARK: File type

    /// A stat's `st_mode` keeps its type apart: the permissions are the same as `chmod`'s, and a directory is known.
    func testStatModeType() {
        let file = FileMode(Int64(S_IFREG) | 0o644)
        XCTAssertEqual(file.permissions, 0o644)
        XCTAssertFalse(file.isDirectory)

        let directory = FileMode(Int64(S_IFDIR) | 0o755)
        XCTAssertEqual(directory.label, "0755 rwxr-xr-x")
        XCTAssertTrue(directory.isDirectory)

        XCTAssertFalse(FileMode(Int64(S_IFLNK) | 0o755).isDirectory)
        XCTAssertFalse(mode(0o755).isDirectory)
    }

    /// An `st_mode` of 0 is no stat, and any other is a mode.
    func testStatModeZeroIsNoStat() {
        XCTAssertNil(FileMode(statMode: Int64(0)))
        XCTAssertEqual(FileMode(statMode: Int64(0o100644))?.permissions, 0o644)
        XCTAssertEqual(FileMode(statMode: Int64(S_IFREG))?.octal, "0000")
    }

    /// Integers of every width and sign are read by bit pattern without trapping.
    func testOutOfRangeDoesNotTrap() {
        XCTAssertEqual(FileMode(Int32(-1)).octal, "7777")
        XCTAssertEqual(FileMode(Int64.min).permissions, 0)
        XCTAssertEqual(FileMode(UInt16(0o100755)).octal, "0755")
        XCTAssertEqual(FileMode(Int64(0x1_0000_0000) | 0o644).octal, "0644")
    }

    // MARK: Callouts

    /// Seen on macOS 27: `chmod 755` on a 644 file has `mode` 0755 and a stat of 0100644, so it was made executable.
    func testChmodPlusXIsMadeExecutable() {
        XCTAssertEqual(added(from: 0o100644, to: 0o755), [.madeExecutable])
        XCTAssertEqual(added(from: 0o100644, to: 0o744), [.madeExecutable])
        XCTAssertEqual(added(from: 0o100600, to: 0o601), [.madeExecutable])
    }

    /// Execute bits the file had already, or taken away, earn nothing; any new execute bit does.
    func testExecuteAlreadySetIsNotCalledOut() {
        XCTAssertEqual(added(from: 0o100755, to: 0o755), [])
        XCTAssertEqual(added(from: 0o100755, to: 0o644), [])
        XCTAssertEqual(added(from: 0o100744, to: 0o755), [.madeExecutable])
        XCTAssertEqual(added(from: 0o100644, to: 0o600), [])
    }

    /// A directory's execute bits are search bits, so making one searchable isn't making it executable.
    func testDirectorySearchIsNotMadeExecutable() {
        XCTAssertEqual(added(from: 0o040700, to: 0o755), [])
        XCTAssertEqual(added(from: 0o040644, to: 0o777), [.worldWritable])
    }

    /// A directory ignores setuid, and its setgid changes nothing on macOS, so neither is called out on one.
    func testDirectorySetuidAndSetgidAreNotCalledOut() {
        XCTAssertEqual(added(from: 0o040755, to: 0o4755), [])
        XCTAssertEqual(added(from: 0o040755, to: 0o2775), [])
        XCTAssertEqual(added(from: 0o040755, to: 0o6755), [])
        XCTAssertEqual(added(from: 0o040755, to: 0o6777), [.worldWritable])
    }

    /// A sticky directory, as `/tmp`'s 1777 is, isn't called out as world-writable; a sticky file still is.
    func testStickyDirectoryIsNotWorldWritable() {
        XCTAssertEqual(added(from: 0o040755, to: 0o1777), [])
        XCTAssertEqual(added(from: 0o041755, to: 0o1777), [])
        XCTAssertEqual(added(from: 0o041777, to: 0o0777), [])
        XCTAssertEqual(added(from: 0o040755, to: 0o0777), [.worldWritable])
        XCTAssertEqual(added(from: 0o100644, to: 0o1666), [.worldWritable])
        XCTAssertEqual(added(from: nil, to: 0o1777), [.madeExecutable, .worldWritable])
    }

    /// Setuid and setgid are called out when added, apart and together, and not when the file had them.
    func testSetuidAndSetgid() {
        XCTAssertEqual(added(from: 0o100755, to: 0o4755), [.setuidAdded])
        XCTAssertEqual(added(from: 0o100755, to: 0o2755), [.setgidAdded])
        XCTAssertEqual(added(from: 0o100755, to: 0o6755), [.setuidAdded, .setgidAdded])
        XCTAssertEqual(added(from: 0o104755, to: 0o4755), [])
        XCTAssertEqual(added(from: 0o104755, to: 0o755), [])
        XCTAssertEqual(added(from: 0o100644, to: 0o4755), [.madeExecutable, .setuidAdded])
    }

    /// Write for others is called out when added; write for the owner or group isn't.
    func testWorldWritable() {
        XCTAssertEqual(added(from: 0o100644, to: 0o646), [.worldWritable])
        XCTAssertEqual(added(from: 0o100644, to: 0o664), [])
        XCTAssertEqual(added(from: 0o100666, to: 0o666), [])
        XCTAssertEqual(added(from: 0o100644, to: 0o777), [.madeExecutable, .worldWritable])
    }

    /// The sticky bit on its own earns nothing.
    func testStickyIsNotCalledOut() {
        XCTAssertEqual(added(from: 0o100644, to: 0o1644), [])
    }

    /// With no stat, nothing can be ruled out, so every bit the new mode sets counts as added.
    func testUnknownPreviousMode() {
        XCTAssertEqual(added(from: nil, to: 0o644), [])
        XCTAssertEqual(added(from: nil, to: 0o755), [.madeExecutable])
        XCTAssertEqual(added(from: nil, to: 0o6777), FileModeCallout.allCases)
        XCTAssertEqual(added(from: 0, to: 0o4700), [.madeExecutable, .setuidAdded])
        XCTAssertEqual(FileModeCallout.added(to: mode(0o2002), from: nil), [.setgidAdded, .worldWritable])
    }

    /// Every bit set earns every callout, in the order of the cases.
    func testOrder() {
        XCTAssertEqual(added(from: 0o100000, to: 0o7777),
                       [.madeExecutable, .setuidAdded, .setgidAdded, .worldWritable])
        XCTAssertEqual(added(from: 0o107777, to: 0o7777), [])
    }
}
