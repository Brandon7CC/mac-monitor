//
//  FileTypeReaderTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
import MachO
@testable import SutroESFramework


// MARK: - Reading a file's type
/// Pins ``FileTypeReader`` on real files: a Mach-O copied from this Mac, a dylib and a bundle from this build, a
/// script, property lists, a zip and an Apple Archive, then what's never read (an empty file, a symbolic link, a
/// directory, a dataless file, a file on a volume that isn't local, one the reader can't read), a file swapped after
/// the event, one renamed after it, a folder above it swapped for a link, and a file changed since the event.
final class FileTypeReaderTests: XCTestCase {
    /// Every volume local, as this Mac's temporary folder is.
    private let volumes = LocalVolumes()

    /// The type of a file as an event's stat of it names it.
    ///
    /// - Parameters:
    ///   - path: The file.
    ///   - info: The event's stat, the file's own by default.
    ///   - reader: Who it's read for, this process's user by default.
    ///   - volumes: The local volumes.
    /// - Returns: The identifier and Mach-O file type, or `nil` when it isn't read.
    /// - Throws: The error from `stat`.
    private func type(of path: String, stat info: stat? = nil, for reader: FileReader? = nil,
                      volumes: LocalVolumes? = nil) throws -> FileType? {
        FileTypeReader.fileType(at: path, stat: try info ?? fileStat(path), for: reader ?? currentReader,
                                volumes: volumes ?? self.volumes)
    }

    // MARK: Binaries

    /// `/bin/ls` is a universal executable whose first slice starts past the first 4 KB: its header is read on its own.
    func testCopiedExecutable() throws {
        let path = try temporaryCopy(of: "/bin/ls")
        let header = Array(try XCTUnwrap(FileHandle(forReadingAtPath: path)?.read(upToCount: 4_096)))
        if FileTypeClassifier.sliceOffsetToRead(header: header) == nil {
            XCTAssertNotNil(MachOHeader.thin(header), "/bin/ls is thin on this Mac")
        }
        XCTAssertEqual(try type(of: path), FileType("com.apple.mach-o-executable", machOType: "MH_EXECUTE"))
    }

    /// This build's framework is a dylib, and its test bundle a bundle.
    func testBuiltDylibAndBundle() throws {
        let framework = try XCTUnwrap(Bundle(for: ESMessage.self).executablePath)
        XCTAssertEqual(try type(of: try temporaryCopy(of: framework)),
                       FileType("com.apple.mach-o-dylib", machOType: "MH_DYLIB"))
        let tests = try XCTUnwrap(Bundle(for: Self.self).executablePath)
        XCTAssertEqual(try type(of: try temporaryCopy(of: tests)),
                       FileType("com.apple.mach-o-bundle", machOType: "MH_BUNDLE"))
    }

    /// This Mac's dyld shared cache, read in place: a root file the test's user can read.
    func testDyldSharedCache() throws {
        let path = "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e"
        try XCTSkipUnless(FileManager.default.isReadableFile(atPath: path), "No arm64e dyld shared cache")
        XCTAssertEqual(try type(of: path), .dyldCache)
    }

    /// A universal binary made up with its slice 16 KB in, and a disk image's trailer at its end: the two extra reads.
    func testExtraReads() throws {
        let slice = FileTypeSamples.machO(MH_DYLIB)
        var universal = FileTypeSamples.universal(sliceAt: 16_384)
        universal += [UInt8](repeating: 0, count: 16_384 - universal.count) + slice
        XCTAssertEqual(try type(of: try temporaryFile(bytes: universal)),
                       FileType("com.apple.mach-o-dylib", machOType: "MH_DYLIB"))
        let image = FileTypeSamples.starting(with: [0x78, 0xDA], length: 8_192) + FileTypeSamples.diskImageTrailer
        XCTAssertEqual(try type(of: try temporaryFile(bytes: image, named: "image.bin")), .diskImage)
        /// A file shorter than a trailer isn't read for one.
        let short = Array(FileTypeSamples.diskImageTrailer.prefix(100)) + [0]
        XCTAssertEqual(try type(of: try temporaryFile(bytes: short)), .data)
    }

    /// A universal header whose 64-bit offset is near `UInt64.max` is a Mach-O binary that names no slice, with no
    /// read past the first: the offset would overflow.
    func testHugeSliceOffset() throws {
        for offset in [UInt64.max, UInt64.max - 16] {
            let header = FileTypeSamples.universal(slices: [(UInt32(bitPattern: CPU_TYPE_ARM64), offset)], wide: true)
            XCTAssertEqual(try type(of: try temporaryFile(bytes: header)), .machOBinary, "\(offset)")
        }
    }

    // MARK: Text and archives

    /// A script, property lists in XML and binary, and a zip `ditto` makes.
    func testScriptPropertyListsAndZip() throws {
        let script = try temporaryFile(bytes: FileTypeSamples.text("#!/bin/zsh\necho 'Mac Monitor'\n"), named: "tool")
        XCTAssertEqual(try type(of: script), FileType("public.zsh-script"))
        let plist: [String: Any] = ["Label": "com.example.agent", "RunAtLoad": true]
        for (format, identifier) in [(PropertyListSerialization.PropertyListFormat.xml, "com.apple.xml-property-list"),
                                     (.binary, "com.apple.binary-property-list")] {
            let data = try PropertyListSerialization.data(fromPropertyList: plist, format: format, options: 0)
            XCTAssertEqual(try type(of: try temporaryFile(bytes: Array(data), named: "agent.plist")),
                           FileType(identifier))
        }
        let zip = try resolvedTemporaryDirectory().appendingPathComponent("script.zip")
        try run("/usr/bin/ditto", ["-c", "-k", script, zip])
        XCTAssertEqual(try type(of: zip), .zip)
    }

    /// `aa archive` compresses with LZFSE by default, and writes `AA01` only uncompressed: both are Apple Archives.
    func testAppleArchives() throws {
        let script = try temporaryFile(bytes: FileTypeSamples.text("#!/bin/sh\necho hi\n"), named: "tool.sh")
        let folder = script.deletingLastPathComponent
        for algorithm in [nil, "raw", "lz4", "zlib"] {
            let archive = folder.appendingPathComponent("tool-\(algorithm ?? "default").aar")
            try run("/usr/bin/aa", ["archive", "-d", folder, "-o", archive, "-include-path", "tool.sh"]
                        + (algorithm.map { ["-a", $0] } ?? []))
            XCTAssertEqual(try type(of: archive), .appleArchive, algorithm ?? "default")
        }
    }

    /// Run a tool and wait for it.
    ///
    /// - Parameters:
    ///   - tool: The tool's path.
    ///   - arguments: Its arguments.
    /// - Throws: The error launching it.
    private func run(_ tool: String, _ arguments: [String]) throws {
        let process = try Foundation.Process.run(URL(fileURLWithPath: tool), arguments: arguments)
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0, "\(tool) \(arguments)")
    }

    // MARK: What isn't read

    /// A file of 0 bytes is empty by the event's stat alone: nothing is opened, so it needn't be there any more.
    func testEmptyFileIsntRead() throws {
        let path = try temporaryFile(bytes: [])
        let info = try fileStat(path)
        XCTAssertEqual(try type(of: path, stat: info), .emptyFile)
        unlink(path)
        XCTAssertEqual(try type(of: path, stat: info), .emptyFile)
    }

    /// A symbolic link, as Endpoint Security's stat of the link names it, isn't read. One swapped in for the file the
    /// event named is a replacement.
    func testSymbolicLinks() throws {
        let target = try temporaryFile(bytes: FileTypeSamples.text("#!/bin/sh\n"))
        let link = target.deletingLastPathComponent.appendingPathComponent("link")
        XCTAssertEqual(symlink(target, link), 0)
        XCTAssertNil(try type(of: link, stat: try fileStat(link, followingLinks: false)))
        XCTAssertEqual(try type(of: link, stat: try fileStat(target)), .replacedFile)
    }

    /// A directory, a dataless file and a file on a volume that isn't local aren't read.
    func testFilesThatArentRead() throws {
        let directory = try makeTemporaryDirectory().path
        XCTAssertNil(try type(of: directory))
        let path = try temporaryFile(bytes: FileTypeSamples.text("hello"))
        var dataless = try fileStat(path)
        dataless.st_flags |= UInt32(SF_DATALESS)
        XCTAssertNil(try type(of: path, stat: dataless))
        XCTAssertNil(try type(of: path, volumes: LocalVolumes(mounts: { [] })))
        let device = try fileStat(path).st_dev
        XCTAssertNil(try type(of: path, volumes: LocalVolumes(mounts: { [(device, false)] })))
        XCTAssertEqual(try type(of: path, volumes: LocalVolumes(mounts: { [(device, true)] })), .plainText)
    }

    /// A `0600` file is read for its owner and for root, and never for another user, whose group can't read it
    /// either.
    func testUnreadableFileIsRefused() throws {
        let path = try temporaryFile(bytes: FileTypeSamples.text("secret"), mode: 0o600)
        XCTAssertEqual(try type(of: path), .plainText)
        XCTAssertEqual(try type(of: path, for: FileReader(uid: 0, gid: 0)), .plainText)
        XCTAssertNil(try type(of: path, for: FileReader(uid: getuid() + 1, gid: getgid())))
    }

    /// A file renamed over the event's between the event and the read is a replacement, and a file deleted since
    /// isn't read.
    func testSwappedAndDeletedFiles() throws {
        let path = try temporaryFile(bytes: FileTypeSamples.text("original"))
        let info = try fileStat(path)
        let decoy = path.deletingLastPathComponent.appendingPathComponent("decoy")
        try Data(FileTypeSamples.machO(MH_EXECUTE)).write(to: URL(fileURLWithPath: decoy))
        XCTAssertEqual(rename(decoy, path), 0)
        XCTAssertEqual(try type(of: path, stat: info), .replacedFile)
        unlink(path)
        XCTAssertNil(try type(of: path, stat: info))
    }

    /// A file renamed after the event, as a writer that saves to a temporary file renames it at once, is read where
    /// it is now, found by its device and inode. Once deleted it has no path, and isn't read.
    func testRenamedFileIsFoundByItsInode() throws {
        let path = try temporaryFile(bytes: FileTypeSamples.machO(MH_DYLIB), named: "ziAbc123")
        let info = try fileStat(path)
        let renamed = path.deletingLastPathComponent.appendingPathComponent("libsample.dylib")
        XCTAssertEqual(rename(path, renamed), 0)
        XCTAssertEqual(FileTypeReader.currentPath(of: info), renamed)
        XCTAssertEqual(try type(of: path, stat: info), FileType("com.apple.mach-o-dylib", machOType: "MH_DYLIB"))
        unlink(renamed)
        XCTAssertNil(FileTypeReader.currentPath(of: info))
        XCTAssertNil(try type(of: path, stat: info))
    }

    /// A folder above the file swapped for a symbolic link after the event is a replacement: the path is never
    /// followed through a link, which could lead to a network volume. So is a path with a link in it from the start,
    /// as `/var/folders` is: Endpoint Security names `/private/var/folders`.
    func testFolderSwappedForALink() throws {
        let folder = try resolvedTemporaryDirectory()
        let inner = folder.appendingPathComponent("x")
        XCTAssertEqual(mkdir(inner, 0o755), 0)
        let path = inner.appendingPathComponent("libsample.dylib")
        try Data(FileTypeSamples.machO(MH_DYLIB)).write(to: URL(fileURLWithPath: path))
        let info = try fileStat(path)
        XCTAssertEqual(try type(of: path, stat: info)?.machOType, "MH_DYLIB")
        let moved = folder.appendingPathComponent("y")
        XCTAssertEqual(rename(inner, moved), 0)
        XCTAssertEqual(symlink(moved, inner), 0)
        XCTAssertEqual(try type(of: path, stat: info), .replacedFile)
        let unresolved = try makeTemporaryDirectory().appendingPathComponent("tool").path
        try Data(FileTypeSamples.text("#!/bin/sh\n")).write(to: URL(fileURLWithPath: unresolved))
        try XCTSkipUnless(unresolved.hasPrefix("/var/"), "The temporary folder isn't under /var: \(unresolved)")
        XCTAssertEqual(try type(of: unresolved), .replacedFile)
    }

    /// The identity check's walk up the path, and its ACL check, never follow a link: a link to a folder isn't one the
    /// reader can search, and a link's ACL is its own, not its target's.
    func testReachingDoesntFollowLinks() throws {
        let folder = try resolvedTemporaryDirectory()
        let real = folder.appendingPathComponent("real"), link = folder.appendingPathComponent("link")
        XCTAssertEqual(mkdir(real, 0o755), 0)
        XCTAssertEqual(symlink(real, link), 0)
        XCTAssertTrue(currentReader.canSearch(try fileStat(link)))
        XCTAssertFalse(currentReader.canSearch(try fileStat(link, followingLinks: false)))
        try run("/bin/chmod", ["+a", "nobody deny search", real])
        XCTAssertTrue(AccessControlList.denies(ACL_SEARCH, at: real))
        XCTAssertFalse(AccessControlList.denies(ACL_SEARCH, at: link))
    }

    /// A file changed between the event and the read gives the type of what's there now, marked as not the event's
    /// version: its size, modification time or change time differ.
    func testChangedSinceTheEvent() throws {
        let path = try temporaryFile(bytes: FileTypeSamples.text("#!/bin/sh\n"))
        let info = try fileStat(path)
        let reading = { (info: stat) in
            FileTypeReader.reading(at: path, stat: info, for: self.currentReader, volumes: self.volumes)
        }
        XCTAssertEqual(reading(info), FileTypeReader.Reading(type: FileType("public.shell-script"), isCurrent: true))
        let changes: [(inout stat) -> Void] = [{ $0.st_size += 1 }, { $0.st_mtimespec.tv_nsec += 1 },
                                               { $0.st_ctimespec.tv_sec -= 1 }]
        for change in changes {
            var changed = info
            change(&changed)
            XCTAssertEqual(reading(changed), FileTypeReader.Reading(type: FileType("public.shell-script"),
                                                                    isCurrent: false))
        }
        XCTAssertEqual(reading(try fileStat(path.deletingLastPathComponent)),
                       FileTypeReader.Reading(type: nil, isCurrent: false))
    }

    // MARK: Volumes and threads

    /// This Mac's mounts include the temporary folder's volume and `/`, both local.
    func testMountedVolumes() throws {
        let mounts = LocalVolumes.mountedVolumes()
        XCTAssertFalse(mounts.isEmpty)
        for path in ["/", NSTemporaryDirectory()] {
            let device = try fileStat(path).st_dev
            XCTAssertEqual(mounts.first { $0.device == device }?.isLocal, true, path)
            XCTAssertTrue(volumes.isLocal(device), path)
        }
        XCTAssertFalse(volumes.isLocal(-12_345))
    }

    /// A volume list is read once for devices it has, and again for one it doesn't.
    func testVolumesAreRemembered() {
        var reads = 0
        let volumes = LocalVolumes(mounts: { reads += 1; return [(1, true), (2, false)] })
        XCTAssertTrue(volumes.isLocal(1))
        XCTAssertFalse(volumes.isLocal(2))
        XCTAssertEqual(reads, 1)
        XCTAssertFalse(volumes.isLocal(3))
        XCTAssertFalse(volumes.isLocal(3))
        XCTAssertEqual(reads, 2)
    }

    /// A read's policies are set only while it runs, then put back as they were: a thread that had one set keeps it,
    /// one that had neither has neither, nested reads included, and a read that throws puts them back too.
    func testReadingThreadPolicy() {
        let done = expectation(description: "done")
        Thread.detachNewThread {
            let atime = IOPOL_TYPE_VFS_ATIME_UPDATES, dataless = IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES
            let before = getiopolicy_np(dataless, IOPOL_SCOPE_THREAD)
            XCTAssertFalse(ReadingThreadPolicy.isApplied)
            ReadingThreadPolicy.whileReading {
                XCTAssertTrue(ReadingThreadPolicy.isApplied)
                ReadingThreadPolicy.whileReading { XCTAssertTrue(ReadingThreadPolicy.isApplied) }
                XCTAssertTrue(ReadingThreadPolicy.isApplied)
            }
            XCTAssertFalse(ReadingThreadPolicy.isApplied)
            XCTAssertEqual(getiopolicy_np(dataless, IOPOL_SCOPE_THREAD), before)
            XCTAssertNotEqual(getiopolicy_np(atime, IOPOL_SCOPE_THREAD), IOPOL_ATIME_UPDATES_OFF)
            do {
                try ReadingThreadPolicy.whileReading { throw POSIXError(.EIO) }
                XCTFail("The read's error is thrown")
            } catch {}
            XCTAssertFalse(ReadingThreadPolicy.isApplied)
            setiopolicy_np(atime, IOPOL_SCOPE_THREAD, IOPOL_ATIME_UPDATES_OFF)
            ReadingThreadPolicy.whileReading {}
            XCTAssertEqual(getiopolicy_np(atime, IOPOL_SCOPE_THREAD), IOPOL_ATIME_UPDATES_OFF)
            XCTAssertEqual(getiopolicy_np(dataless, IOPOL_SCOPE_THREAD), before)
            done.fulfill()
        }
        wait(for: [done], timeout: 10)
    }
}
