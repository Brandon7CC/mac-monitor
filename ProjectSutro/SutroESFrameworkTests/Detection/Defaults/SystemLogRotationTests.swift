//
//  SystemLogRotationTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/9/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Rotated system logs
/// Pins what Archive written leaves out in ``Indicator/systemLogFolder``: macOS rotating its system logs every night,
/// which a Mac with its code signing checks on recorded as bzip2 (`com.apple.bzcat`) writing `wifi.log.0.bz2` and
/// aslmanager writing `system.log.0.gz`, and the macOS 27.0 test VM as bzip2 (`com.apple.bzip2`) writing
/// `wifi.log.0.bz2` when `newsyslog -F` forced a rotation. Only the ``Indicator/logRotators``, as macOS's own, are
/// left out, and only there: macOS's other archivers writing in the log folder still match, as does a lookalike that
/// isn't a platform binary or is adhoc signed, and a log rotator writing an archive anywhere else. AppleScript
/// written doesn't change. The Security Extension's compiled set and Mac Monitor's own matching agree on every case.
final class SystemLogRotationTests: XCTestCase {
    /// The code signing flags macOS 27.2 reports, through Endpoint Security, for a program re-signed adhoc with
    /// `codesign -s -`: `CS_VALID`, `CS_ADHOC`, `CS_KILL`, `CS_NO_UNTRUSTED_HELPERS` and `CS_SIGNED`.
    private static let adhocFlags: Int64 = 0x2200_0203
    /// Rotated logs, a compressed file in a folder of the log folder, the folder spelled in capitals, and a name that
    /// isn't ASCII, which takes Foundation's `LIKE`, each with the type its content is named by.
    private static let rotatedLogs = [("/private/var/log/wifi.log.0.bz2", FileType.bzip2),
                                      ("/private/var/log/system.log.0.gz", .gzip),
                                      ("/private/var/log/asl/Logs/rotated.0.gz", .gzip),
                                      ("/PRIVATE/VAR/LOG/install.log.0.gz", .gzip),
                                      ("/private/var/log/wïfi.log.1.bz2", .bzip2)]

    /// The log rotators are exactly aslmanager, bzip2 by both of its signing IDs, macOS 27.0's and 27.2's, and gzip:
    /// newsyslog runs bzip2 or gzip, and writes no archive.
    func testLogRotators() {
        XCTAssertEqual(Indicator.logRotators, ["com.apple.aslmanager", "com.apple.bzip2", "com.apple.bzcat",
                                               "com.apple.gzip"])
    }

    /// macOS's own log rotators writing rotated logs don't match Archive written.
    func testRotatedLogsAreLeftOut() throws {
        for (path, type) in Self.rotatedLogs {
            for rotator in Indicator.logRotators {
                let close = try derivedClose(at: path, type: type.identifier, by: (rotator, true))
                try assertArchiveWritten(close, false, rotator + " " + path)
            }
        }
    }

    /// macOS's other archivers and copiers writing an archive in the log folder still match, as root staging there
    /// with built-in tools would.
    func testOtherPlatformWritersInTheLogFolderMatch() throws {
        let writers = ["com.apple.zip", "com.apple.ditto", "com.apple.bsdtar", "com.apple.aa", "com.apple.cp",
                       "com.apple.curl", "com.apple.newsyslog", "com.apple.hdiutil"]
        for writer in writers {
            let close = try derivedClose(at: "/private/var/log/loot.gz", type: FileType.gzip.identifier,
                                         by: (writer, true))
            try assertArchiveWritten(close, true, writer)
        }
    }

    /// A log rotator's lookalike, not a platform binary, or one but adhoc signed, as every process is a platform
    /// binary with the code signing checks off, writing in the log folder still matches.
    func testLookalikesInTheLogFolderMatch() throws {
        for (path, type) in Self.rotatedLogs {
            let unsigned = try derivedClose(at: path, type: type.identifier, by: ("com.apple.bzcat", false))
            try assertArchiveWritten(unsigned, true, "not a platform binary " + path)
            let adhoc = adhocSigned(try derivedClose(at: path, type: type.identifier, by: ("com.apple.bzcat", true)))
            XCTAssertTrue(adhoc.process.is_adhoc_signed, path)
            try assertArchiveWritten(adhoc, true, "adhoc " + path)
        }
    }

    /// A log rotator writing an archive outside the log folder still matches, a folder that only starts with its name
    /// included.
    func testArchivesElsewhereMatch() throws {
        let paths = ["/Users/marcus/loot.bz2", "/private/var/logs/loot.gz", "/private/var/log.gz",
                     "/private/tmp/var/log/loot.gz"]
        for path in paths {
            let close = try derivedClose(at: path, type: FileType.gzip.identifier, by: ("com.apple.gzip", true))
            try assertArchiveWritten(close, true, path)
        }
    }

    /// A compiled script written in the log folder still matches AppleScript written.
    func testAppleScriptInTheLogFolderMatches() throws {
        let close = try derivedClose(at: "/private/var/log/loot.scpt", type: FileType.compiledAppleScript.identifier,
                                     by: ("com.apple.osacompile", true))
        try assertShippedMatch(close, true, id: try shippedID("AppleScript written"), "a script in the log folder")
        try assertArchiveWritten(close, false, "a script in the log folder")
    }
}


// MARK: - Deriving and checking closes
extension SystemLogRotationTests {
    /// A close with its process re-signed adhoc, and what Mac Monitor derives from its signing derived again.
    ///
    /// - Parameter message: The close.
    /// - Returns: The close.
    private func adhocSigned(_ message: Message) -> Message {
        var message = message
        message.process.codesigning_flags = Self.adhocFlags
        message.process.team_id = nil
        message.process.enrich()
        return message
    }

    /// Check Archive written matches a close as expected, with the extension and the app agreeing.
    ///
    /// - Parameters:
    ///   - message: The close.
    ///   - matches: Should it match?
    ///   - label: What the case is.
    /// - Throws: The error storing the event, or a failure when Archive written isn't shipped.
    private func assertArchiveWritten(_ message: Message, _ matches: Bool, _ label: String) throws {
        try assertShippedMatch(message, matches, id: try shippedID("Archive written"), label)
    }
}
