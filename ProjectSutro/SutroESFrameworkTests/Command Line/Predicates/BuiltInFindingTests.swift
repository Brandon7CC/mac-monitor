//
//  BuiltInFindingTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/26/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Built-in marks
/// Pins the built-in marks that took over the event tables' hard-coded labels. Each matches the event its label marked
/// and not a near miss. A saved set loses them, a twin is drawn once, and the stored event is matched as its record is.
final class BuiltInFindingTests: XCTestCase {
    /// - Parameters:
    ///   - type: An event type, without `ES_EVENT_TYPE_NOTIFY_`.
    ///   - values: The record's other values.
    /// - Returns: The record.
    private func event(_ type: String, _ values: [String: Any] = [:]) -> NSDictionary {
        values.merging(["es_event_type": "ES_EVENT_TYPE_NOTIFY_" + type]) { $1 } as NSDictionary
    }

    /// - Parameters:
    ///   - target: The new process's values.
    ///   - exec: The exec's other values.
    /// - Returns: An exec's record.
    private func exec(_ target: [String: Any], _ exec: [String: Any] = [:]) -> NSDictionary {
        event("EXEC", ["event": ["exec": exec.merging(["target": target]) { $1 }]])
    }

    /// Each label's event, and a near miss, by the built-in mark that marks it now.
    private var cases: [(String, NSDictionary, NSDictionary)] {
        let btm = "/private/var/db/com.apple.backgroundtaskmanagement"
        let image = "/private/var/folders/T\\/NSCreateObjectFileImageFromMemory-x"
        let archiver: [String: Any] = ["executable": ["name": "ArchiveService"], "file_quarantine_type": "DISABLED"]
        let optIn: [String: Any] = ["file_quarantine_type": "OPT_IN"]
        func file(_ type: String, _ key: String, _ quarantined: Int, _ path: String, _ process: [String: Any] = [:])
            -> NSDictionary {
            event(type, ["target_path": path, "process": process, "event": [key: ["is_quarantined": quarantined]]])
        }
        return [
            ("Root user", exec(["ruid": 0]), exec(["ruid": 501])),
            ("Elevated to root", exec(["euid": 0, "ruid": 501]), exec(["euid": 0, "ruid": 0])),
            ("DYLD_INSERT_LIBRARIES", exec([:], ["env": ["HOME=/var/root", "DYLD_INSERT_LIBRARIES=/tmp/a.dylib"]]),
             exec([:], ["env": ["DYLD_LIBRARY_PATH=/tmp"]])),
            ("File Quarantine-aware", exec(["file_quarantine_type": "OPT_IN"]),
             exec(["file_quarantine_type": "DISABLED"])),
            ("File Quarantine-aware process", exec(["file_quarantine_type": "OPT_IN"]),
             exec(["file_quarantine_type": "DISABLED"])),
            ("New executable", exec([:], ["executable_age_ms": 3_250]), exec([:], ["executable_age_ms": -5])),
            ("Ran a script", exec([:], ["script_content": "echo"]), exec([:], ["script_content": ""])),
            ("Reflective loading image", file("CREATE", "create", 0, image), file("WRITE", "write", 0, image)),
            ("Unquarantined file created", file("CREATE", "create", 0, "/Users/a/Downloads\\/a.app", archiver),
             file("CREATE", "create", 0, "/private/var/folders/T\\/a.app", archiver)),
            ("Unquarantined file created", file("CREATE", "create", 0, "/Users/a/x", optIn),
             file("CREATE", "create", 0, image, optIn)),
            ("Quarantined file", file("CREATE", "create", 1, "/Users/a/x"), file("CREATE", "create", 1, image)),
            ("OSA component mapped", event("MMAP", ["target_path": "/System/Library/ScriptingAdditions/a.osax/a"]),
             event("MMAP", ["target_path": "/usr/lib/libSystem.B.dylib"])),
            ("Quarantined file renamed", file("RENAME", "rename", 1, "/Users/a/x"),
             file("RENAME", "rename", 0, "/Users/a/x")),
            ("Unquarantined app bundle", file("RENAME", "rename", 0, "/Applications\\/X.app"),
             file("RENAME", "rename", 1, "/Applications\\/X.app")),
            ("BTM database modified", file("RENAME", "rename", 0, btm + "\\/BackgroundItems-v13.btm"),
             file("RENAME", "rename", 1, btm + "\\/BackgroundItems-v13.btm")),
            ("Quarantine attribute deleted",
             event("DELETEEXTATTR", ["event": ["deleteextattr": ["extattr": "com.apple.quarantine"]]]),
             event("DELETEEXTATTR", ["event": ["deleteextattr": ["extattr": "com.apple.quarantine.x"]]])),
            ("Login Item written", event("WRITE", ["target_path": "/private/var/folders/backgroundtaskmanagementd/a"]),
             event("WRITE", ["target_path": btm + "/BackgroundItems-v13.btm"])),
            ("Background item added", event("BTM_LAUNCH_ITEM_ADD"), event("BTM_LAUNCH_ITEM_REMOVE")),
            ("Background item removed", event("BTM_LAUNCH_ITEM_REMOVE"), event("BTM_LAUNCH_ITEM_ADD")),
            ("XProtect malware", event("XP_MALWARE_REMEDIATED"), event("MOUNT")),
            ("HID device opened",
             event("IOKIT_OPEN", ["event": ["iokit_open": ["user_client_class": "IOHIDLibUserClient"]]]),
             event("IOKIT_OPEN", ["event": ["iokit_open": ["user_client_class": "IOSurfaceRootUserClient"]]])),
            ("Remote thread created", event("REMOTE_THREAD_CREATE"), event("GET_TASK")),
            ("Code signature invalidated", event("CS_INVALIDATED"), event("EXEC")),
            ("Process traced", event("TRACE"), event("PROC_CHECK")),
            ("Task port retrieved", event("GET_TASK"), event("GET_TASK_READ")),
            ("Non-zero exit", event("EXIT", ["event": ["exit": ["stat": 256]]]),
             event("EXIT", ["event": ["exit": ["stat": 0]]])),
        ]
    }

    /// Each built-in mark matches the event its label marked, and not a near miss.
    func testEachMatchesItsLabelsEvent() throws {
        for (name, matching, other) in cases {
            let finding = try XCTUnwrap(Finding.builtInMarks.first { $0.name == name }, name)
            XCTAssertTrue(finding.showsInTables && finding.isEnabled, name)
            let predicate = try StreamFilter.Predicate(finding.predicate, for: .finding)
            XCTAssertTrue(try predicate.evaluate(on: matching), name)
            XCTAssertFalse(try predicate.evaluate(on: other), name)
        }
    }

    /// One key path compares with another, on a record and on the stored event alike.
    func testKeyPathComparesWithKeyPath() throws {
        let source = "event.exec.dyld_exec_path != event.exec.target.executable.path"
        let predicate = try StreamFilter.Predicate(source, for: .finding)
        XCTAssertTrue(StoredEventValues.canEvaluate(predicate.parsed))
        let target = ["executable": ["path": "/bin/a"]]
        XCTAssertTrue(try predicate.evaluate(on: exec(target, ["dyld_exec_path": "/b"])))
        XCTAssertFalse(try predicate.evaluate(on: exec(target, ["dyld_exec_path": "/bin/a"])))
    }

    /// A stored exec and file event, changed as each label's event was, are matched on the stored event as on its
    /// record.
    func testStoredEventsMatchAsTheirRecords() throws {
        let corpus = try SyntheticCorpus.records()
        var execMessage = try XCTUnwrap(corpus.first { $0.label == "exec (full)" }?.message)
        guard case .exec(var exec) = execMessage.event else { return XCTFail("not an exec") }
        exec.env.append("DYLD_INSERT_LIBRARIES=/tmp/a.dylib")
        exec.dyld_exec_path = "/tmp/elsewhere"
        exec.target.ruid = 0
        execMessage.event = .exec(exec)
        var create = try XCTUnwrap(corpus.first { $0.label == "create (full)" }?.message)
        guard case .create(var event) = create.event else { return XCTFail("not a create") }
        event.is_quarantined = 0
        create.event = .create(event)
        create.process.file_quarantine_type = .disabled
        create.process.executable?.path = "/System/Library/CoreServices/ArchiveService"
        create.target_path = "/Users/a/Downloads/x"
        let names = ["DYLD_INSERT_LIBRARIES", "Root user", "Unquarantined file created"]
        let findings = Finding.builtInMarks.filter { names.contains($0.name) }
        for finding in findings {
            let predicate = try StreamFilter.Predicate(finding.predicate, for: .finding)
            XCTAssertTrue(StoredEventValues.canEvaluate(predicate.parsed), finding.name)
        }
        try withEventStore([execMessage, create]) { _, stored in
            let found = Set(stored.flatMap { FindingMatcher(findings).matches($0).map(\.name) })
            XCTAssertEqual(found, Set(names))
        }
    }

    /// Each built-in mark has its own identity and keeps its number. Each default with a twin shares its name,
    /// predicate and symbol.
    func testBuiltInMarksKeepTheirNumbers() throws {
        let twins = Finding.builtInMarks.filter { mark in Finding.defaults.contains { $0.id == mark.id } }
        XCTAssertEqual(Set(Finding.builtInMarks.map(\.id)).count, Finding.builtInMarks.count)
        XCTAssertEqual(Finding.builtInMarks.count, 25)
        XCTAssertEqual(Set(twins.map(\.name)), ["New executable", "Ran a script"])
        /// 18, 32 and 33 were the dyld exec path mismatch and the adhoc and unsigned warnings, now removed.
        for number in (15...37).filter({ ![18, 32, 33].contains($0) }) {
            let id = try XCTUnwrap(UUID(uuidString: String(format: "6D4D0F1D-0000-4000-8000-%012X", number)))
            XCTAssertTrue(Finding.builtInMarks.contains { $0.id == id }, "\(number)")
        }
        for twin in twins {
            let finding = try XCTUnwrap(Finding.defaults.first { $0.id == twin.id })
            XCTAssertEqual([twin.predicate, twin.symbol, twin.name], [finding.predicate, finding.symbol, finding.name])
        }
    }

    /// A finding that marks the tables and is a twin of a mark drawn beside it is drawn once, as the mark, unless its
    /// symbol changed. The rest are drawn.
    func testTwinsDrawOnce() throws {
        let script = try XCTUnwrap(Finding.defaults.first { $0.name == "Ran a script" })
        let age = try XCTUnwrap(Finding.defaults.first { $0.name == "New executable" })
        let mark = try XCTUnwrap(Finding.labelMarks.first { $0.id == age.id })
        let own = Finding(name: "Mine", explanation: "", symbol: "star", color: .red, predicate: "process.pid == 1",
                          correlation: true, groups: false, tables: true)
        XCTAssertEqual(Finding.findings([age, script, own], besides: [mark]), [script, own])
        var changed = age
        changed.symbol = "clock"
        XCTAssertEqual(Finding.findings([changed], besides: [mark]), [changed])
        XCTAssertEqual(mark.palette, [.orange, .primary])
        XCTAssertEqual(mark.explanation, "Its executable was {age} old at exec.")
    }

    /// Each place draws its own marks, as its label did. The process name draws root and elevation. The event type's
    /// label draws the rest. Both draw the dyld injection mark.
    func testEachPlaceDrawsItsMarks() {
        let label = Set(Finding.labelMarks.map(\.name))
        let name = Set(Finding.nameMarks.map(\.name))
        XCTAssertEqual(label.intersection(name), ["DYLD_INSERT_LIBRARIES"])
        XCTAssertTrue(name.isSuperset(of: ["Root user", "Elevated to root"]))
        XCTAssertFalse(label.contains("Root user"))
    }
}
