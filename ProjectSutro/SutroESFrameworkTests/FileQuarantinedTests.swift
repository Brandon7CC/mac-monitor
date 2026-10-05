//
//  FileQuarantinedTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Is a file quarantined?
/// Pins ``ProcessHelpers/isFileQuarantined(filePath:)`` (1 quarantined, 0 not, 2 no file) to what it answered when it
/// asked `FileManager` whether the file exists before reading the attribute, for every shape of path.
final class FileQuarantinedTests: XCTestCase {
    /// The answer as Mac Monitor computed it before: does the file exist, then is its attribute non-empty?
    ///
    /// - Parameter path: The file's path.
    /// - Returns: 1, 0, or 2.
    private func formerAnswer(_ path: String) -> Int {
        guard FileManager.default.fileExists(atPath: path) else { return 2 }
        return getxattr(path, "com.apple.quarantine", nil, 0, 0, 0) > 0 ? 1 : 0
    }
    
    /// Give a file or directory a `com.apple.quarantine` attribute.
    ///
    /// - Parameters:
    ///   - path: Its path.
    ///   - value: The attribute's value; empty for an attribute with no bytes.
    /// - Throws: The `POSIXError` setting it.
    private func quarantine(_ path: String, value: String = "0083;66ff0000;Safari;") throws {
        let result = value.withCString { setxattr(path, "com.apple.quarantine", $0, strlen($0), 0, 0) }
        if result != 0 { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }
    
    /// Files with and without the attribute, an empty attribute, directories, symbolic links (to a quarantined file,
    /// broken, and in a loop), missing files, a file used as a directory, a directory that can't be searched, and odd
    /// paths all get the answer they got before.
    ///
    /// - Throws: The error making the files.
    func testEveryPathShapeAnswersAsBefore() throws {
        let directory = try makeTemporaryDirectory().path
        let manager = FileManager.default
        let quarantined = directory + "/Download.zip", plain = directory + "/Notes.txt"
        let empty = directory + "/Empty.txt", folder = directory + "/Folder", quarantinedFolder = directory + "/App.app"
        let locked = directory + "/Locked"
        for path in [quarantined, plain, empty] { try Data("example".utf8).write(to: URL(fileURLWithPath: path)) }
        for path in [folder, quarantinedFolder, locked] {
            try manager.createDirectory(atPath: path, withIntermediateDirectories: false)
        }
        try Data("example".utf8).write(to: URL(fileURLWithPath: locked + "/Inside.txt"))
        try quarantine(quarantined)
        try quarantine(empty, value: "")
        try quarantine(quarantinedFolder)
        try manager.createSymbolicLink(atPath: directory + "/Link", withDestinationPath: quarantined)
        try manager.createSymbolicLink(atPath: directory + "/Broken", withDestinationPath: directory + "/Missing")
        try manager.createSymbolicLink(atPath: directory + "/Loop", withDestinationPath: directory + "/Loop")
        chmod(locked, 0)
        /// Searchable again before the temporary directory is removed (teardown blocks run last in, first out).
        addTeardownBlock { chmod(locked, 0o755) }
        
        let paths = [
            quarantined, plain, empty, folder, quarantinedFolder, folder + "/", quarantined + "/", plain + "/child",
            directory + "/Link", directory + "/Broken", directory + "/Loop", directory + "/Missing",
            locked + "/Inside.txt", directory + "\\/Notes.txt", directory + "//Download.zip",
            directory + "/./Download.zip", "", "/", "relative/path", quarantined + "\u{0}suffix", plain + "\u{0}",
            "/" + String(repeating: "a", count: 2_000),
        ]
        for path in paths {
            XCTAssertEqual(ProcessHelpers.isFileQuarantined(filePath: path), formerAnswer(path), path)
        }
        XCTAssertEqual(ProcessHelpers.isFileQuarantined(filePath: quarantined), 1)
        XCTAssertEqual(ProcessHelpers.isFileQuarantined(filePath: plain), 0)
        XCTAssertEqual(ProcessHelpers.isFileQuarantined(filePath: directory + "/Missing"), 2)
    }
}
