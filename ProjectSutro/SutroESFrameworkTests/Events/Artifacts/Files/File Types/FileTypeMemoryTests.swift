//
//  FileTypeMemoryTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
import MachO
@testable import SutroESFramework


// MARK: - A capture lane's file types
/// Pins ``FileTypeMemory``: an mmap of a file seen before reads nothing, a changed file is read again even with its
/// modification time put back, only types read from the event's version of a file are remembered, each reader gets
/// the answer its own read would, a close is never looked up, a rename takes the type of the close that wrote the
/// version it moves or else reads the file where it now is, and the memory is bounded.
final class FileTypeMemoryTests: XCTestCase {
    /// A dylib in a temporary folder.
    ///
    /// - Returns: Its path and stat.
    /// - Throws: The error writing it.
    private func dylib() throws -> (path: String, info: stat) {
        let path = try temporaryFile(bytes: FileTypeSamples.machO(MH_DYLIB), named: "libsample.dylib")
        return (path, try fileStat(path))
    }

    /// A file mapped again is remembered by its stat alone: deleted since, it still has its type.
    func testHitReadsNothing() throws {
        let memory = FileTypeMemory()
        let (path, info) = try dylib()
        let expected = FileType("com.apple.mach-o-dylib", machOType: "MH_DYLIB")
        XCTAssertEqual(memory.mappedFileType(at: path, stat: info, for: currentReader), expected)
        unlink(path)
        XCTAssertEqual(memory.mappedFileType(at: path, stat: info, for: currentReader), expected)
        XCTAssertEqual(memory.count, 1)
    }

    /// A new modification time or size is a new version of the file, read again.
    func testChangedFileIsReadAgain() throws {
        let memory = FileTypeMemory()
        let (path, info) = try dylib()
        _ = memory.mappedFileType(at: path, stat: info, for: currentReader)
        /// Rewritten in place, so its device and inode stay the event's.
        let file = try XCTUnwrap(FileHandle(forWritingAtPath: path))
        try file.truncate(atOffset: 0)
        try file.write(contentsOf: FileTypeSamples.text("#!/bin/sh\n"))
        try file.close()
        var touched = info
        touched.st_mtimespec.tv_nsec += 1
        let script = FileType("public.shell-script")
        XCTAssertEqual(memory.mappedFileType(at: path, stat: touched, for: currentReader), script)
        var resized = info
        resized.st_size += 1
        XCTAssertEqual(memory.mappedFileType(at: path, stat: resized, for: currentReader), script)
        XCTAssertEqual(memory.mappedFileType(at: path, stat: info, for: currentReader)?.machOType, "MH_DYLIB")
    }

    /// Overwrite a file in place with bytes of the same size, then put its modification time back, as `touch -r`
    /// would: only its change time says it changed.
    ///
    /// - Parameters:
    ///   - path: The file.
    ///   - bytes: Its new contents, as long as the old.
    ///   - info: Its stat before, whose modification time is put back.
    /// - Throws: The error writing it, or the `POSIXError` of `utimensat`.
    private func overwrite(_ path: String, with bytes: [UInt8], restoring info: stat) throws {
        let file = try XCTUnwrap(FileHandle(forWritingAtPath: path))
        try file.write(contentsOf: Data(bytes))
        try file.close()
        let times = [info.st_atimespec, info.st_mtimespec]
        guard utimensat(AT_FDCWD, path, times, 0) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    /// A same-size file rewritten in place, with its old modification time put back, is a new version by its change
    /// time: a text file swapped for a dylib this way is read again, not given the text's type.
    func testRewriteWithItsModificationTimeRestored() throws {
        let memory = FileTypeMemory()
        let text = FileTypeSamples.text(String(repeating: "a", count: MachOHeader.sliceHeaderLength - 1) + "\n")
        let path = try temporaryFile(bytes: text, named: "libsample.dylib")
        let info = try fileStat(path)
        XCTAssertEqual(memory.mappedFileType(at: path, stat: info, for: currentReader), .plainText)
        try overwrite(path, with: FileTypeSamples.machO(MH_DYLIB), restoring: info)
        let rewritten = try fileStat(path)
        XCTAssertEqual(rewritten.st_size, info.st_size)
        XCTAssertEqual(rewritten.st_mtimespec.tv_sec, info.st_mtimespec.tv_sec)
        XCTAssertEqual(rewritten.st_mtimespec.tv_nsec, info.st_mtimespec.tv_nsec)
        XCTAssertEqual(memory.mappedFileType(at: path, stat: rewritten, for: currentReader),
                       FileType("com.apple.mach-o-dylib", machOType: "MH_DYLIB"))
        XCTAssertEqual(memory.count, 2)
    }

    /// A file that changed between the event and the read gives what's there now, but isn't remembered under the
    /// event's version: a later mmap of that version reads it again.
    func testChangedBeforeTheReadIsntRemembered() throws {
        let memory = FileTypeMemory()
        let (path, info) = try dylib()
        try overwrite(path, with: FileTypeSamples.machO(MH_BUNDLE), restoring: info)
        XCTAssertEqual(memory.mappedFileType(at: path, stat: info, for: currentReader)?.machOType, "MH_BUNDLE")
        XCTAssertEqual(memory.count, 0)
        let truncated = try XCTUnwrap(FileHandle(forWritingAtPath: path))
        try truncated.truncate(atOffset: 0)
        try truncated.close()
        XCTAssertEqual(memory.mappedFileType(at: path, stat: info, for: currentReader), .emptyFile)
        XCTAssertEqual(memory.count, 0, "an empty read isn't remembered for a version that had bytes")
    }

    /// Each reader has its own answer: a type remembered from one user's mmap isn't given to another the file is
    /// refused to.
    func testEachReaderHasItsOwnAnswer() throws {
        let memory = FileTypeMemory()
        let path = try temporaryFile(bytes: FileTypeSamples.machO(MH_BUNDLE), mode: 0o600)
        let info = try fileStat(path)
        XCTAssertEqual(memory.mappedFileType(at: path, stat: info, for: currentReader)?.machOType, "MH_BUNDLE")
        let other = FileReader(uid: getuid() + 1, gid: getgid())
        XCTAssertNil(memory.mappedFileType(at: path, stat: info, for: other))
        XCTAssertEqual(memory.mappedFileType(at: path, stat: info, for: FileReader(uid: 0, gid: 0))?.machOType,
                       "MH_BUNDLE")
        XCTAssertEqual(memory.count, 2)
    }

    /// A file refused to one process isn't remembered as unreadable, nor is a replaced one.
    func testOnlyTypesReadAreRemembered() throws {
        let memory = FileTypeMemory()
        let path = try temporaryFile(bytes: FileTypeSamples.machO(MH_BUNDLE), mode: 0o600)
        let info = try fileStat(path)
        XCTAssertNil(memory.mappedFileType(at: path, stat: info, for: FileReader(uid: getuid() + 1, gid: getgid())))
        XCTAssertEqual(memory.count, 0)
        XCTAssertEqual(memory.mappedFileType(at: path, stat: info, for: currentReader)?.machOType, "MH_BUNDLE")
        var other = info
        other.st_ino += 1
        XCTAssertEqual(memory.mappedFileType(at: path, stat: other, for: currentReader), .replacedFile)
        XCTAssertEqual(memory.count, 1)
        XCTAssertNil(memory.mappedFileType(at: path, stat: try fileStat(path.deletingLastPathComponent),
                                           for: currentReader))
        XCTAssertEqual(memory.count, 1)
    }

    /// A modified close's file has just changed: it's read, never looked up.
    func testCloseIsNeverLookedUp() throws {
        let memory = FileTypeMemory()
        let (path, info) = try dylib()
        XCTAssertNotNil(memory.mappedFileType(at: path, stat: info, for: currentReader))
        unlink(path)
        XCTAssertNil(memory.closedFileType(at: path, stat: info, for: currentReader))
    }

    /// A file closed and then renamed into place is named by its close's read, with no read of its own: gone since, it
    /// still has its type. Its close's stat is the version the rename moves, which a mapping of it doesn't push out.
    func testRenameAfterItsCloseReadsNothing() throws {
        let memory = FileTypeMemory(capacity: 1)
        let (path, info) = try dylib()
        let expected = FileType("com.apple.mach-o-dylib", machOType: "MH_DYLIB")
        XCTAssertEqual(memory.closedFileType(at: path, stat: info, for: currentReader), expected)
        XCTAssertEqual(memory.closedCount, 1)
        let other = try dylib()
        _ = memory.mappedFileType(at: other.path, stat: other.info, for: currentReader)
        _ = memory.mappedFileType(at: try dylib().path, stat: try dylib().info, for: currentReader)
        unlink(path)
        XCTAssertEqual(memory.renamedFileType(at: path + ".renamed", stat: info, for: currentReader), expected)
    }

    /// A rename with no close before it reads the file where it now is, by its stat from before the rename, which
    /// the rename itself changes: the type isn't remembered. One of a changed version of a closed file is read too.
    func testRenameWithoutItsCloseReadsTheDestination() throws {
        let memory = FileTypeMemory()
        let (path, info) = try dylib()
        let destination = path + ".moved"
        XCTAssertEqual(rename(path, destination), 0)
        XCTAssertEqual(memory.renamedFileType(at: destination, stat: info, for: currentReader)?.machOType, "MH_DYLIB")
        XCTAssertEqual(memory.closedCount, 0)
        XCTAssertEqual(memory.count, 0)
        unlink(destination)
        XCTAssertNil(memory.renamedFileType(at: destination, stat: info, for: currentReader))
        var changed = info
        changed.st_size += 1
        _ = memory.closedFileType(at: destination, stat: info, for: currentReader)
        XCTAssertNil(memory.renamedFileType(at: destination, stat: changed, for: currentReader))
    }

    /// Two generations: a file found in the older moves to the newer, and one in neither is read again.
    func testGenerations() throws {
        let memory = FileTypeMemory(capacity: 1)
        let files = try (0..<3).map { _ in try dylib() }
        for file in files { _ = memory.mappedFileType(at: file.path, stat: file.info, for: currentReader) }
        XCTAssertEqual(memory.count, 2)
        files.forEach { unlink($0.path) }
        XCTAssertNil(memory.mappedFileType(at: files[0].path, stat: files[0].info, for: currentReader))
        XCTAssertNotNil(memory.mappedFileType(at: files[1].path, stat: files[1].info, for: currentReader))
        XCTAssertNotNil(memory.mappedFileType(at: files[2].path, stat: files[2].info, for: currentReader))
    }
}
