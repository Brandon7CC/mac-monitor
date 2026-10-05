//
//  MuteFileReaderTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Importing mute files
/// Pins Import: a version 1 file, or the one `ESMutedPath` per line list Mac Monitor exported before 2.2 (and the
/// files in "Mute sets/"), read leniently with a sentence for each thing left out.
final class MuteFileReaderTests: XCTestCase {
    /// A legacy line.
    ///
    /// - Parameters:
    ///   - path: The path.
    ///   - type: The type name.
    ///   - events: The event names.
    ///   - extra: More keys, as JSON, such as the 13.3.1 export's `id`.
    /// - Returns: The line.
    private func line(_ path: String, _ type: String = "ES_MUTE_PATH_TYPE_LITERAL", _ events: [String] = [],
                      extra: String = "") -> String {
        let names = events.map { "\"\($0)\"" }.joined(separator: ",")
        return #"{"eventCount":\#(events.count),"events":[\#(names)],"path":"\#(path)","type":"\#(type)"\#(extra)}"#
    }
    
    /// Import some text.
    ///
    /// - Parameter text: The file.
    /// - Returns: What it holds.
    /// - Throws: ``MuteFileError``.
    private func read(_ text: String) throws -> MuteImport {
        try MuteFileReader.read(Data(text.utf8))
    }
    
    /// The error importing some text throws.
    ///
    /// - Parameter text: The file.
    /// - Returns: The error, if it's a ``MuteFileError``.
    private func error(_ text: String) -> MuteFileError? {
        do {
            _ = try read(text)
            return nil
        } catch {
            return error as? MuteFileError
        }
    }
    
    /// An entry from Apple's default set, which names only AUTH events, is left out with a warning; a 13.3.1 style
    /// line with an `id` reads; a global entry reads as every event.
    ///
    /// - Throws: An unexpected ``MuteFileError``.
    func testLegacyShapesFromMuteSets() throws {
        let apple = line("/usr/sbin/spindump", "ES_MUTE_PATH_TYPE_TARGET_LITERAL",
                         ["ES_EVENT_TYPE_AUTH_OPEN", "ES_EVENT_TYPE_AUTH_UNLINK"])
        let old = line("/usr/libexec/opendirectoryd", "ES_MUTE_PATH_TYPE_LITERAL", ["ES_EVENT_TYPE_NOTIFY_OPEN"],
                       extra: #","id":"926D9832-06B4-43CF-9D91-921EE6E9D6C4""#)
        let imported = try read([apple, old, line("/usr/libexec/logd")].joined(separator: "\n"))
        XCTAssertEqual(imported.format, .legacy)
        XCTAssertEqual(imported.list, MuteList([
            PathMute(path: "/usr/libexec/opendirectoryd", type: ES_MUTE_PATH_TYPE_LITERAL,
                     events: [ES_EVENT_TYPE_NOTIFY_OPEN]),
            PathMute(path: "/usr/libexec/logd", type: ES_MUTE_PATH_TYPE_LITERAL)
        ]))
        XCTAssertEqual(imported.warnings.count, 1)
        XCTAssertTrue(imported.warnings[0].hasPrefix("Left out “/usr/sbin/spindump”"), imported.warnings[0])
    }
    
    /// Endpoint Security lists a path muted for every event with every type it has, AUTH events and unnamed ones
    /// included: such an entry reads as every event, without warnings.
    ///
    /// - Throws: An unexpected ``MuteFileError``.
    func testAnEntryNamingEveryCapturedEventReadsAsEveryEvent() throws {
        let everything = (0..<ES_EVENT_TYPE_LAST.rawValue).map {
            eventTypeToString(from: es_event_type_t(rawValue: $0))
        }
        let captured = supportedEvents.map { eventTypeToString(from: $0) }
        let imported = try read([line("/a", "ES_MUTE_PATH_TYPE_LITERAL", everything),
                                 line("/b", "ES_MUTE_PATH_TYPE_PREFIX", captured),
                                 line("/c", "ES_MUTE_PATH_TYPE_PREFIX", Array(captured.dropFirst()))]
                                    .joined(separator: "\n"))
        XCTAssertEqual(imported.list.scopes[MuteList.Key(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL)], .allEvents)
        XCTAssertEqual(imported.list.scopes[MuteList.Key(path: "/b", type: ES_MUTE_PATH_TYPE_PREFIX)], .allEvents)
        XCTAssertNotEqual(imported.list.scopes[MuteList.Key(path: "/c", type: ES_MUTE_PATH_TYPE_PREFIX)], .allEvents)
        XCTAssertEqual(imported.warnings, [])
    }
    
    /// A target entry naming every event that can be muted by target path reads as every event.
    ///
    /// - Throws: An unexpected ``MuteFileError``.
    func testATargetEntryNamingEveryTargetableEventReadsAsEveryEvent() throws {
        let targetable = MuteFileReader.everyEvent(for: ES_MUTE_PATH_TYPE_TARGET_PREFIX).map {
            eventTypeToString(from: $0)
        }
        let imported = try read(line("/a", "ES_MUTE_PATH_TYPE_TARGET_PREFIX", targetable))
        XCTAssertEqual(imported.list.scopes.values.first, .allEvents)
    }
    
    /// Blank lines and CRLF line ends are fine; a line that isn't a muted path fails the import with its number.
    func testLineEndsAndBrokenLines() throws {
        let crlf = [line("/a"), "", line("/b"), "   "].joined(separator: "\r\n")
        XCTAssertEqual(try read(crlf).list.count, 2)
        XCTAssertEqual(error([line("/a"), "", "{\"path\": \"/c\"}"].joined(separator: "\n")),
                       .invalidLine(line: 3, reason: "“type” is missing"))
        XCTAssertEqual(error([line("/a"), "not json"].joined(separator: "\r\n")),
                       .invalidLine(line: 2, reason: "it isn't valid JSON"))
    }
    
    /// Unknown names (and `ES_EVENT_TYPE_LAST`, which Endpoint Security lists for types Mac Monitor can't name) are
    /// left out and the known ones kept; an entry naming only unknown events is left out.
    ///
    /// - Throws: An unexpected ``MuteFileError``.
    func testUnknownEventNamesAreLeftOut() throws {
        let imported = try read([
            line("/a", "ES_MUTE_PATH_TYPE_LITERAL", ["ES_EVENT_TYPE_NOTIFY_OPEN", "ES_EVENT_TYPE_LAST"]),
            line("/b", "ES_MUTE_PATH_TYPE_LITERAL", ["ES_EVENT_TYPE_NOTIFY_FUTURE"])
        ].joined(separator: "\n"))
        XCTAssertEqual(imported.list.mutes, [PathMute(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL,
                                                      events: [ES_EVENT_TYPE_NOTIFY_OPEN])])
        XCTAssertEqual(imported.warnings.count, 2)
        XCTAssertTrue(imported.warnings[1].hasPrefix("Left out “/b”"), imported.warnings[1])
    }
    
    /// A version 1 file is recognized pretty printed or on one line; a single legacy line is legacy; text that is
    /// neither gets the version 1 error, and a list that starts as a legacy one gets the legacy error.
    ///
    /// - Throws: An unexpected ``MuteFileError``.
    func testFormatSniffing() throws {
        let list = MuteList([PathMute(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL)])
        XCTAssertEqual(try MuteFileReader.read(MuteFile(list).encoded()).format, .current)
        XCTAssertEqual(try read(#"{"version":1,"mutes":[{"path":"/a","type":"ES_MUTE_PATH_TYPE_LITERAL"}]}"#).list,
                       list)
        XCTAssertEqual(try read(line("/a")).format, .legacy)
        XCTAssertEqual(error("garbage"), .malformed("it isn't valid JSON"))
        XCTAssertEqual(error(#"{"version": 2, "mutes": []}"#), .unsupportedVersion(2))
        XCTAssertEqual(error([line("/a"), "garbage"].joined(separator: "\n")),
                       .invalidLine(line: 2, reason: "it isn't valid JSON"))
        XCTAssertEqual(error(" \n"), .malformed("the file is empty"))
    }
    
    /// A version 1 file is imported leniently too: an entry that can't be used is left out with a warning.
    ///
    /// - Throws: An unexpected ``MuteFileError``.
    func testVersionOneImportIsLenient() throws {
        let file = MuteFile(mutes: [.init(path: "relative", type: "ES_MUTE_PATH_TYPE_LITERAL"),
                                    .init(path: "/ok", type: "ES_MUTE_PATH_TYPE_LITERAL")])
        let imported = try MuteFileReader.read(file.encoded())
        XCTAssertEqual(imported.list.mutes.map(\.path), ["/ok"])
        XCTAssertEqual(imported.warnings.count, 1)
    }
}
