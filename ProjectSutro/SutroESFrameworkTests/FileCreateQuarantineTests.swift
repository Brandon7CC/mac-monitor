//
//  FileCreateQuarantineTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Quarantine of created files
/// Pins `is_quarantined` (Mac Monitor's addition) on create events: 1 when the created file has a
/// `com.apple.quarantine` extended attribute, 0 when it has none, 2 when there's no such file. A new path (of a create
/// or a rename) is the directory and the file name joined by one "/".
final class FileCreateQuarantineTests: XCTestCase {
    /// The quarantine value Safari writes, as `xattr -p com.apple.quarantine` shows it.
    private static let quarantine = "0083;66ff0000;Safari;"
    
    /// Write a file in `directory`, with a `com.apple.quarantine` extended attribute or without one.
    ///
    /// - Parameters:
    ///   - name: The file's name.
    ///   - directory: Its directory.
    ///   - quarantined: Give it the attribute?
    /// - Throws: The error writing the file, or the `POSIXError` setting the attribute.
    private func makeFile(_ name: String, in directory: URL, quarantined: Bool) throws {
        let url = directory.appendingPathComponent(name)
        try Data("example".utf8).write(to: url)
        guard quarantined else { return }
        let result = Self.quarantine.withCString { setxattr(url.path, "com.apple.quarantine", $0, strlen($0), 0, 0) }
        if result != 0 { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }
    
    /// A create event for a new path, as Endpoint Security describes one after the file is created.
    ///
    /// - Parameters:
    ///   - directory: The new file's directory.
    ///   - name: The new file's name.
    /// - Returns: The event.
    private func createdNewPath(in directory: String, named name: String) -> FileCreateEvent {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CREATE)
        fixture.message.pointee.event.create.destination_type = ES_DESTINATION_TYPE_NEW_PATH
        fixture.message.pointee.event.create.destination.new_path.dir = fixture.file(directory)
        fixture.message.pointee.event.create.destination.new_path.filename = fixture.token(name)
        fixture.message.pointee.event.create.destination.new_path.mode = 0o644
        return FileCreateEvent(from: fixture.raw)
    }
    
    /// A new path's quarantine is read from the created file itself.
    ///
    /// - Throws: The error making the files.
    func testNewPath() throws {
        let directory = try makeTemporaryDirectory()
        try makeFile("Download.zip", in: directory, quarantined: true)
        try makeFile("Notes.txt", in: directory, quarantined: false)
        XCTAssertEqual(createdNewPath(in: directory.path, named: "Download.zip").is_quarantined, 1)
        XCTAssertEqual(createdNewPath(in: directory.path, named: "Notes.txt").is_quarantined, 0)
        XCTAssertEqual(createdNewPath(in: directory.path, named: "Missing.txt").is_quarantined, 2)
    }
    
    /// An existing file's quarantine is read from its path, as before.
    ///
    /// - Throws: The error making the file.
    func testExistingFile() throws {
        let directory = try makeTemporaryDirectory()
        try makeFile("Download.zip", in: directory, quarantined: true)
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CREATE)
        fixture.message.pointee.event.create.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE
        fixture.message.pointee.event.create.destination.existing_file =
            fixture.file(directory.appendingPathComponent("Download.zip").path)
        XCTAssertEqual(FileCreateEvent(from: fixture.raw).is_quarantined, 1)
    }
    
    /// A new path's full path has one "/" between the directory and the name, also for a directory ending in "/".
    func testFullPath() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CREATE)
        for (directory, expected) in [("/private/tmp", "/private/tmp/a.txt"), ("/private/tmp/", "/private/tmp/a.txt"),
                                      ("/", "/a.txt")] {
            fixture.message.pointee.event.create.destination.new_path.dir = fixture.file(directory)
            fixture.message.pointee.event.create.destination.new_path.filename = fixture.token("a.txt")
            XCTAssertEqual(NewPath(from: fixture.message.pointee.event.create).fullPath, expected)
        }
    }
    
    /// A rename to a new path names the same full path as its destination, also in the root directory.
    func testRenameDestinationPath() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_RENAME)
        fixture.message.pointee.event.rename.source = fixture.file("/private/tmp/a.txt")
        fixture.message.pointee.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH
        for (directory, expected) in [("/private/tmp", "/private/tmp/b.txt"), ("/", "/b.txt")] {
            fixture.message.pointee.event.rename.destination.new_path.dir = fixture.file(directory)
            fixture.message.pointee.event.rename.destination.new_path.filename = fixture.token("b.txt")
            XCTAssertEqual(FileRenameEvent(from: fixture.raw).destination_path, expected)
        }
    }
}
