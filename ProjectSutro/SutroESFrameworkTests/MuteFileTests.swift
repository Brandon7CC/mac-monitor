//
//  MuteFileTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Mute file format
/// Pins mute file version 1: its exact bytes, what it accepts and refuses, and how each entry is checked against what
/// Endpoint Security and Mac Monitor's clients can use.
final class MuteFileTests: XCTestCase {
    /// A two-entry file, byte for byte.
    private let golden = """
        {
          "mutes" : [
            {
              "events" : [

              ],
              "path" : "/usr/libexec/logd",
              "type" : "ES_MUTE_PATH_TYPE_LITERAL"
            },
            {
              "events" : [
                "ES_EVENT_TYPE_NOTIFY_MMAP"
              ],
              "path" : "/Library/Caches/",
              "type" : "ES_MUTE_PATH_TYPE_TARGET_PREFIX"
            }
          ],
          "version" : 1
        }

        """
    
    /// Read a file's mutes.
    ///
    /// - Parameters:
    ///   - json: The file.
    ///   - strictness: What to do with what can't be used.
    /// - Returns: The list and its warnings.
    /// - Throws: ``MuteFileError``.
    private func read(_ json: String, _ strictness: MuteFile.Strictness = .strict) throws
        -> (list: MuteList, warnings: [String]) {
        try MuteFile.decode(Data(json.utf8)).list(strictness)
    }
    
    /// A file with one entry.
    ///
    /// - Parameters:
    ///   - path: The entry's path.
    ///   - type: Its type name.
    ///   - events: Its event names.
    /// - Returns: The file's JSON.
    private func file(path: String = "/a", type: String = "ES_MUTE_PATH_TYPE_LITERAL",
                      events: [String] = []) -> String {
        String(decoding: MuteFile(mutes: [.init(path: path, type: type, events: events)]).encoded(), as: UTF8.self)
    }
    
    /// The error reading a file throws.
    ///
    /// - Parameters:
    ///   - json: The file.
    ///   - strictness: What to do with what can't be used.
    /// - Returns: The error, if it's a ``MuteFileError``.
    private func error(_ json: String, _ strictness: MuteFile.Strictness = .strict) -> MuteFileError? {
        do {
            _ = try read(json, strictness)
            return nil
        } catch {
            return error as? MuteFileError
        }
    }
    
    /// Mac Monitor's default set writes and reads back as the same list, with nothing to warn about.
    ///
    /// - Throws: An unexpected ``MuteFileError``.
    func testShippedDefaultRoundTrips() throws {
        let (list, warnings) = try read(String(decoding: MuteFile(.testDefault).encoded(), as: UTF8.self))
        XCTAssertEqual(list, .testDefault)
        XCTAssertEqual(warnings, [])
    }
    
    /// The same list always gives the same bytes: pretty printed, sorted keys, unescaped slashes, a final newline.
    func testEncodingIsByteStable() {
        let list = MuteList([PathMute(path: "/Library/Caches/", type: ES_MUTE_PATH_TYPE_TARGET_PREFIX,
                                      events: [ES_EVENT_TYPE_NOTIFY_MMAP]),
                             PathMute(path: "/usr/libexec/logd", type: ES_MUTE_PATH_TYPE_LITERAL)])
        XCTAssertEqual(String(decoding: MuteFile(list).encoded(), as: UTF8.self), golden)
        XCTAssertEqual(MuteFile(list).encoded(), MuteFile(MuteList(list.mutes.reversed())).encoded())
    }
    
    /// Missing events and an empty list both mean every event; unknown keys are ignored.
    ///
    /// - Throws: An unexpected ``MuteFileError``.
    func testMissingEventsMeanEveryEventAndUnknownKeysAreIgnored() throws {
        let json = """
            {"version": 1, "comment": "mine", "mutes": [
              {"path": "/a", "type": "ES_MUTE_PATH_TYPE_LITERAL", "note": "x"},
              {"path": "/b", "type": "ES_MUTE_PATH_TYPE_LITERAL", "events": []}]}
            """
        let (list, _) = try read(json)
        XCTAssertEqual(list, MuteList([PathMute(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL),
                                       PathMute(path: "/b", type: ES_MUTE_PATH_TYPE_LITERAL)]))
    }
    
    /// Entries for the same path and type merge.
    ///
    /// - Throws: An unexpected ``MuteFileError``.
    func testEntriesForTheSameKeyMerge() throws {
        let json = """
            {"version": 1, "mutes": [
              {"path": "/a", "type": "ES_MUTE_PATH_TYPE_LITERAL", "events": ["ES_EVENT_TYPE_NOTIFY_OPEN"]},
              {"path": "/a", "type": "ES_MUTE_PATH_TYPE_LITERAL", "events": ["ES_EVENT_TYPE_NOTIFY_CLOSE"]}]}
            """
        XCTAssertEqual(try read(json).list.scopes.values.first,
                       .events([ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE]))
    }
    
    /// A newer version, a missing or zero version, missing mutes, and a top-level array are refused.
    func testFormatErrors() {
        XCTAssertEqual(error(#"{"version": 2, "mutes": []}"#), .unsupportedVersion(2))
        XCTAssertEqual(error(#"{"version": 2}"#), .unsupportedVersion(2))
        XCTAssertEqual(error(#"{"mutes": []}"#), .malformed("“version” is missing"))
        XCTAssertEqual(error(#"{"version": 0, "mutes": []}"#), .malformed("“version” is 0"))
        XCTAssertEqual(error(#"{"version": 1}"#), .malformed("“mutes” is missing"))
        XCTAssertEqual(error(#"[]"#), .malformed("it isn't a JSON object with “version” and “mutes”"))
        XCTAssertEqual(error("nope"), .malformed("it isn't valid JSON"))
        XCTAssertEqual(error(#"{"version": 1, "mutes": [{"path": "/a"}]}"#), .malformed("“mutes.0.type” is missing"))
        XCTAssertTrue("\(MuteFileError.unsupportedVersion(2))".contains("newer Mac Monitor"))
    }
    
    /// Over 1 MiB is refused before parsing, and over 4,096 mutes once merged.
    func testLimits() {
        let tooLarge = Data(count: MuteLimits.maxFileBytes + 1)
        XCTAssertThrowsError(try MuteFile.decode(tooLarge)) { error in
            XCTAssertEqual(error as? MuteFileError, .tooLarge(bytes: MuteLimits.maxFileBytes + 1))
        }
        let entries = (0...MuteLimits.maxMutes).map {
            MuteFile.Entry(path: "/m/\($0)", type: "ES_MUTE_PATH_TYPE_LITERAL")
        }
        XCTAssertThrowsError(try MuteFile(mutes: entries).list(.lenient)) { error in
            XCTAssertEqual(error as? MuteFileError, .tooManyMutes(MuteLimits.maxMutes + 1))
        }
        XCTAssertNoThrow(try MuteFile(mutes: Array(entries.dropLast())).list(.strict))
    }
    
    /// A mute names at most 512 events, duplicates included, and each name counts once: a request repeating names
    /// can't make checking it slow.
    ///
    /// - Throws: An unexpected ``MuteFileError``.
    func testEventNamesAreCappedAndCountedOnce() throws {
        let open = "ES_EVENT_TYPE_NOTIFY_OPEN", auth = "ES_EVENT_TYPE_AUTH_OPEN"
        let crowded = file(events: Array(repeating: open, count: MuteLimits.maxEventsPerMute + 1))
        XCTAssertEqual(error(crowded), .invalidMute(index: 0, reason: """
            “/a” (ES_MUTE_PATH_TYPE_LITERAL) names more than \(MuteLimits.maxEventsPerMute) events
            """))
        let repeated = Array(repeating: [auth, open], count: MuteLimits.maxEventsPerMute / 2).flatMap { $0 }
        let (list, warnings) = try read(file(events: repeated))
        XCTAssertEqual(list.mutes, [PathMute(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL,
                                             events: [ES_EVENT_TYPE_NOTIFY_OPEN])])
        XCTAssertEqual(warnings, ["""
            “/a” (ES_MUTE_PATH_TYPE_LITERAL): left out AUTH events (\(auth)), which Mac Monitor never receives.
            """])
    }
    
    /// A path must be absolute, without a NUL, and at most `PATH_MAX` bytes; a type must be an Endpoint Security name.
    func testInvalidPathsAndTypesAreRefused() {
        for path in ["", "tmp/x", "/a\0b", "/" + String(repeating: "x", count: MuteLimits.maxPathBytes)] {
            guard case .invalidMute(index: 0, _)? = error(file(path: path)) else {
                return XCTFail("\(path.prefix(10)) was accepted")
            }
        }
        XCTAssertNoThrow(try read(file(path: "/" + String(repeating: "x", count: MuteLimits.maxPathBytes - 1))))
        XCTAssertEqual(error(file(type: "literal")),
                       .invalidMute(index: 0, reason: "“/a” (literal) has an unknown mute type"))
        XCTAssertEqual("\(error(file(path: "tmp/x"))!)",
                       "Mute 1 can't be used: “tmp/x” (ES_MUTE_PATH_TYPE_LITERAL) isn't an absolute path.")
    }
    
    /// An unknown event is refused on the wire, and left out of the saved file with a warning, which leaves out an
    /// entry naming no other event.
    ///
    /// - Throws: An unexpected ``MuteFileError``.
    func testUnknownEvents() throws {
        let mixed = file(events: ["ES_EVENT_TYPE_NOTIFY_OPEN", "ES_EVENT_TYPE_NOTIFY_FUTURE"])
        guard case .invalidMute? = error(mixed) else { return XCTFail("an unknown event was accepted") }
        let (list, warnings) = try read(mixed, .saved)
        XCTAssertEqual(list.mutes, [PathMute(path: "/a", type: ES_MUTE_PATH_TYPE_LITERAL,
                                             events: [ES_EVENT_TYPE_NOTIFY_OPEN])])
        XCTAssertEqual(warnings.count, 1)
        let (none, left) = try read(file(events: ["ES_EVENT_TYPE_NOTIFY_FUTURE"]), .saved)
        XCTAssertTrue(none.isEmpty)
        XCTAssertTrue(left[0].hasPrefix("Left out “/a”"), left[0])
    }
    
    /// AUTH events are left out with a warning, and an entry naming only AUTH events is refused.
    ///
    /// - Throws: An unexpected ``MuteFileError``.
    func testAuthEventsAreLeftOut() throws {
        guard case .invalidMute? = error(file(events: ["ES_EVENT_TYPE_AUTH_OPEN"])) else {
            return XCTFail("an AUTH-only mute was accepted")
        }
        let (list, warnings) = try read(file(events: ["ES_EVENT_TYPE_AUTH_OPEN", "ES_EVENT_TYPE_NOTIFY_OPEN"]))
        XCTAssertEqual(list.mutes.first?.events, [ES_EVENT_TYPE_NOTIFY_OPEN])
        XCTAssertEqual(warnings.count, 1)
        XCTAssertTrue(warnings[0].contains("ES_EVENT_TYPE_AUTH_OPEN"), warnings[0])
    }
    
    /// A target mute leaves out events Endpoint Security can't mute by target path, and is refused if none is left.
    ///
    /// - Throws: An unexpected ``MuteFileError``.
    func testTargetMutesKeepOnlyTargetableEvents() throws {
        let target = "ES_MUTE_PATH_TYPE_TARGET_PREFIX"
        guard case .invalidMute? = error(file(type: target, events: ["ES_EVENT_TYPE_NOTIFY_EXIT"])) else {
            return XCTFail("an untargetable event was accepted")
        }
        let (list, warnings) = try read(file(type: target,
                                             events: ["ES_EVENT_TYPE_NOTIFY_OPEN", "ES_EVENT_TYPE_NOTIFY_EXIT"]))
        XCTAssertEqual(list.mutes.first?.events, [ES_EVENT_TYPE_NOTIFY_OPEN])
        XCTAssertTrue(warnings[0].contains("ES_EVENT_TYPE_NOTIFY_EXIT"), warnings[0])
        XCTAssertEqual(try read(file(type: target)).list.count, 1)
    }
    
    /// A path under `/tmp`, `/var` or `/etc` warns that Endpoint Security matches resolved paths, except in the saved
    /// file.
    ///
    /// - Throws: An unexpected ``MuteFileError``.
    func testUnresolvedPathsWarn() throws {
        let warnings = try read(file(path: "/tmp/x")).warnings
        XCTAssertEqual(warnings.count, 1)
        XCTAssertTrue(warnings[0].hasSuffix("Use “/private/tmp/x”."), warnings[0])
        XCTAssertEqual(try read(file(path: "/var")).warnings.count, 1)
        XCTAssertEqual(try read(file(path: "/variable")).warnings, [])
        XCTAssertEqual(try read(file(path: "/private/etc/x")).warnings, [])
        XCTAssertEqual(try read(file(path: "/etc/x"), .saved).warnings, [])
    }
    
    /// Lenient reading leaves out what it can't use, with a sentence for each, instead of refusing the file.
    ///
    /// - Throws: An unexpected ``MuteFileError``.
    func testLenientReadingLeavesOutInvalidEntries() throws {
        let entries = [MuteFile.Entry(path: "relative", type: "ES_MUTE_PATH_TYPE_LITERAL"),
                       MuteFile.Entry(path: "/ok", type: "ES_MUTE_PATH_TYPE_LITERAL")]
        let (list, warnings) = try MuteFile.list(from: entries, .lenient)
        XCTAssertEqual(list.mutes.map(\.path), ["/ok"])
        XCTAssertEqual(warnings, ["Left out “relative” (ES_MUTE_PATH_TYPE_LITERAL): it isn't an absolute path."])
        XCTAssertThrowsError(try MuteFile.list(from: entries, .saved))
    }
}
