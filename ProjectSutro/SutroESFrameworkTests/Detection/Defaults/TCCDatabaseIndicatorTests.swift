//
//  TCCDatabaseIndicatorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - TCC database modified
/// Pins TCC database modified on events derived from two that `macmonitor stream` recorded on macOS 27
/// (``derived(_:at:by:modified:)``): writes of a TCC database or a file beside it by tccd, by other processes and by a
/// copy of tccd, a rename over one or over a whole TCC folder, and look-alike paths. The Security Extension's compiled
/// set and Mac Monitor's own matching agree on every one and leave none undetermined, a hit is stamped as a shipped
/// medium indicator, and the rule is looked up by the database's file names and the TCC folder's, so no other file
/// event is evaluated against it.
final class TCCDatabaseIndicatorTests: XCTestCase {
    /// The fixture: say's modified close of its SQLite cache's `-shm` (as user 501), then backgroundtaskmanagementd's
    /// rename of its database over the one before (as root), as Mac Monitor 3.1 recorded them.
    private static let fixture = "macmonitor-3.1-close-rename.jsonl"
    /// The system's TCC folder.
    private static let system = "/Library/Application Support/com.apple.TCC/"
    /// A home folder's TCC folder.
    private static let home = "/Users/marcus" + system

    /// A recorded event the derived ones start from: its line in ``fixture``.
    private enum Recorded: Int {
        case close, rename
    }

    /// A process that writes a file, as its record names it.
    private struct Writer {
        /// Its executable's path.
        let path: String
        /// Its signing ID.
        let signingID: String
        /// Is it a platform binary?
        let isPlatform: Bool

        /// tccd, as macOS runs it.
        static let tccd = Writer(path: Indicator.tccd, signingID: "com.apple.tccd", isPlatform: true)
    }

    /// Each derived event is a write of a TCC database exactly when it's a modified close of, or a rename onto,
    /// `TCC.db` or a file beside it, in the system's, root's or a home folder's TCC folder, or a rename onto that
    /// folder, by anything but tccd, which is its path, its signing ID and a platform binary: in the extension and in
    /// the app alike, with every indicator decided.
    func testDerivedWritesMatch() throws {
        let id = try shippedID("TCC database modified")
        let copy = Writer(path: "/private/tmp/tccd", signingID: "com.apple.tccd", isPlatform: true)
        let resigned = Writer(path: "/Users/marcus/tccd", signingID: "tccd", isPlatform: false)
        let impostor = Writer(path: Indicator.tccd, signingID: "com.example.tccd", isPlatform: true)
        let cases: [(String, Message, Bool)] = [
            ("tccd closes the system database", try derived(.close, at: Self.system + "TCC.db", by: .tccd), false),
            ("tccd closes a home folder's", try derived(.close, at: Self.home + "TCC.db-wal", by: .tccd), false),
            ("tccd renames over it", try derived(.rename, at: Self.home + "TCC.db", by: .tccd), false),
            ("say closes a home folder's", try derived(.close, at: Self.home + "TCC.db"), true),
            ("say closes the -wal", try derived(.close, at: Self.home + "TCC.db-wal"), true),
            ("say closes the -shm", try derived(.close, at: Self.home + "TCC.db-shm"), true),
            ("say closes the -journal", try derived(.close, at: Self.home + "TCC.db-journal"), true),
            ("say closes the system's -wal", try derived(.close, at: Self.system + "TCC.db-wal"), true),
            ("a rename over the system's", try derived(.rename, at: Self.system + "TCC.db"), true),
            ("a rename over root's", try derived(.rename, at: "/private/var/root" + Self.system + "TCC.db"), true),
            ("a rename spelled in lowercase", try derived(.rename, at: Self.home + "tcc.db"), true),
            ("a copy of tccd elsewhere", try derived(.close, at: Self.system + "TCC.db", by: copy), true),
            ("a copy re-signed ad hoc", try derived(.close, at: Self.home + "TCC.db", by: resigned), true),
            ("another signing ID at its path", try derived(.close, at: Self.system + "TCC.db", by: impostor), true),
            ("a folder renamed over a home folder's", try derived(.rename, at: String(Self.home.dropLast())), true),
            ("a folder renamed over the system's", try derived(.rename, at: String(Self.system.dropLast())), true),
            ("tccd renames a folder over it", try derived(.rename, at: String(Self.home.dropLast()), by: .tccd),
             false),
            ("a folder renamed to a backup", try derived(.rename, at: "/Users/marcus/Library/Application Support/"
                                                         + "com.apple.TCC.bak"), false),
            ("an unmodified close", try derived(.close, at: Self.home + "TCC.db", modified: false), false),
            ("a backup folder", try derived(.close, at: "/Users/marcus/Library/Application Support/com.apple.TCC.bak/"
                                            + "TCC.db"), false),
            ("a backup file", try derived(.rename, at: Self.home + "TCC.db.backup"), false),
            ("a home folder's backup", try derived(.close, at: "/Users/marcus/Backups/Users/marcus/Library/"
                                                   + "Application Support/com.apple.TCC/TCC.db"), false),
            ("another volume", try derived(.close, at: "/Volumes/Mac" + Self.system + "TCC.db"), false),
            ("another database", try derived(.close, at: Self.system + "REG.db"), false),
        ]
        var values = MessageValueCache()
        for (label, message, matches) in cases {
            let evaluation = Self.shippedIndicators.evaluate(message, values: &values)
            XCTAssertEqual(evaluation.undetermined, [], label)
            XCTAssertEqual(evaluation.hits.map(\.id), try matcherHits(message), label)
            XCTAssertEqual(evaluation.hits.contains { $0.id == id }, matches, label)
        }
    }

    /// The recorded events, as they are, aren't writes of a TCC database, every indicator is decided on them, and the
    /// rule isn't evaluated on them at all: neither path ends in a TCC database's file.
    func testRecordedEventsAreLeftAlone() throws {
        let indicator = try XCTUnwrap(Indicator.defaults.first { $0.name == "TCC database modified" })
        let alone = CompiledIndicators([indicator])
        var values = MessageValueCache()
        for message in try fixtureMessages(Self.fixture) {
            let evaluation = Self.shippedIndicators.evaluate(message, values: &values)
            XCTAssertEqual(evaluation.undetermined, [], message.target_path ?? "")
            XCTAssertFalse(evaluation.hits.contains { $0.id == indicator.id }, message.target_path ?? "")
            XCTAssertEqual(alone.candidates(for: message, values: &values), [], message.target_path ?? "")
        }
    }

    /// A write is stamped as the Security Extension stamps it: the indicator's name, medium, Defense Evasion's
    /// T1548.006, shipped and unedited, and the verdict survives the wire.
    func testWriteIsStampedAsShippedMedium() throws {
        let id = try shippedID("TCC database modified")
        var message = try derived(.close, at: Self.home + "TCC.db")
        var values = MessageValueCache()
        Self.shippedIndicators.stamp(&message, values: &values)
        let hit = try XCTUnwrap(message.indicators?.hits.first { $0.id == id })
        XCTAssertEqual(hit.name, "TCC database modified")
        XCTAssertEqual(hit.severity, .medium)
        XCTAssertEqual(hit.tactic_id, "TA0005")
        XCTAssertEqual(hit.technique, "T1548.006")
        XCTAssertTrue(hit.isDefault)
        XCTAssertFalse(hit.edited)
        assertStamped(message.indicators)
        XCTAssertEqual(try JSONDecoder().decode(Message.self, from: JSONEncoder().encode(message)).indicators,
                       message.indicators)
    }

    /// The rule runs on closes, renames and links, and on each the index looks it up by the end of the path alone,
    /// ignoring case: the four files in a TCC folder, and on a rename the TCC folder itself too.
    func testRuleIsAnchoredOnTheDatabaseFiles() throws {
        let indicator = try XCTUnwrap(Indicator.defaults.first { $0.name == "TCC database modified" })
        let rule = try IndicatorCompiler.compile(indicator.predicate).get()
        let types = [ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_LINK]
            .map { Int($0.rawValue) }
        XCTAssertEqual(Set(rule.types), Set(types))
        let folder = "targetPath suffix folded /library/application support/com.apple.tcc"
        let files = ["tcc.db", "tcc.db-wal", "tcc.db-shm", "tcc.db-journal"].map { folder + "/" + $0 }
        for type in types {
            let anchors = type == Int(ES_EVENT_TYPE_NOTIFY_RENAME.rawValue) ? files + [folder] : files
            guard case .anyOf(let found) = rule.program.necessity(eventType: type) else {
                return XCTFail("Not anchored on \(type)")
            }
            let described = found.map { anchor in
                let bytes = rule.program.bytes[Int(anchor.offset)..<Int(anchor.offset + anchor.length)]
                let folded = anchor.folding ? "folded " : ""
                return "\(anchor.field) \(anchor.shape) \(folded)\(String(decoding: bytes, as: UTF8.self))"
            }
            XCTAssertEqual(described, anchors, "\(type)")
        }
    }

    // MARK: Derived events
    /// An event derived from one recorded in ``fixture``: the recorded record with only its paths and, when one is
    /// given, its process changed, read as File > Open Trace... reads it. No write of a TCC database was recorded,
    /// since the test Mac's owner doesn't change TCC on it, so these stand in for one. The one unmodified close also
    /// turns the recorded close's `modified` off, as a close is recorded when the close filter is off.
    ///
    /// - Parameters:
    ///   - recorded: The recorded event.
    ///   - path: The file closed, or the rename's destination, which replaces an existing file.
    ///   - writer: The process that writes it, or `nil` for the recorded one (say, or backgroundtaskmanagementd).
    ///   - modified: Was the closed file written?
    /// - Returns: The event.
    /// - Throws: The error reading the fixture or the derived record.
    private func derived(_ recorded: Recorded, at path: String, by writer: Writer? = nil,
                         modified: Bool = true) throws -> Message {
        let lines = String(decoding: try fixture(Self.fixture), as: UTF8.self).split(separator: "\n")
        let record = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(lines[recorded.rawValue].utf8),
                                                                options: .mutableContainers) as? NSMutableDictionary)
        let name = (path as NSString).lastPathComponent
        record["target_path"] = path
        switch recorded {
        case .close:
            record["context"] = path
            record.setValue(path, forKeyPath: "event.close.target.path")
            record.setValue(name, forKeyPath: "event.close.target.name")
            record.setValue(modified, forKeyPath: "event.close.modified")
        case .rename:
            record["context"] = "\(name) → \(name)"
            record.setValue(path, forKeyPath: "event.rename.destination_path")
            record.setValue(path, forKeyPath: "event.rename.destination.existing_file.path")
            record.setValue(name, forKeyPath: "event.rename.destination.existing_file.name")
            record.setValue("/private/tmp/" + name, forKeyPath: "event.rename.source.path")
            record.setValue(name, forKeyPath: "event.rename.source.name")
        }
        if let writer {
            record.setValue(writer.path, forKeyPath: "process.executable.path")
            record.setValue((writer.path as NSString).lastPathComponent, forKeyPath: "process.executable.name")
            record.setValue(writer.signingID, forKeyPath: "process.signing_id")
            record.setValue(writer.isPlatform, forKeyPath: "process.is_platform_binary")
            record.setValue(writer.isPlatform ? "PLATFORM" : "ADHOC", forKeyPath: "process.codesigning_type")
        }
        return try TraceImporter.message(from: JSONSerialization.data(withJSONObject: record))
    }
}
