//
//  BuiltInIndicatorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/26/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Built-in marks
/// Pins the built-in marks that took over the event tables' hard-coded labels. Each matches the event its label marked
/// and not a near miss. A saved set loses them, a twin is drawn once, and the stored event is matched as its record is.
final class BuiltInIndicatorTests: XCTestCase {
    /// - Parameters:
    ///   - type: An event type, without `ES_EVENT_TYPE_NOTIFY_`.
    ///   - values: The record's other values.
    /// - Returns: The record.
    private func event(_ type: String, _ values: [String: Any] = [:]) -> NSDictionary {
        (values.merging(["es_event_type": "ES_EVENT_TYPE_NOTIFY_" + type]) { $1 } as NSDictionary).withPayload
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
        let image = "/private/var/folders/T/NSCreateObjectFileImageFromMemory-x"
        let archiver: [String: Any] = ["executable": ["name": "ArchiveService"], "file_quarantine_type": "DISABLED"]
        let optIn: [String: Any] = ["file_quarantine_type": "OPT_IN"]
        func file(_ type: String, _ key: String, _ quarantined: Int, _ path: String, _ process: [String: Any] = [:])
            -> NSDictionary {
            event(type, ["target_path": path, "process": process, "event": [key: ["is_quarantined": quarantined]]])
        }
        return [
            ("Root user", exec(["ruid": 0]), exec(["ruid": 501])),
            ("Elevated to root", exec(["euid": 0, "ruid": 501]), exec(["euid": 0, "ruid": 0])),
            ("Dylib inserted", exec([:], ["env": ["HOME=/var/root", "DYLD_INSERT_LIBRARIES=/tmp/a.dylib"]]),
             exec([:], ["env": ["DYLD_LIBRARY_PATH=/tmp"]])),
            ("File Quarantine-aware", exec(["file_quarantine_type": "OPT_IN"]),
             exec(["file_quarantine_type": "DISABLED"])),
            ("File Quarantine-aware process", exec(["file_quarantine_type": "OPT_IN"]),
             exec(["file_quarantine_type": "DISABLED"])),
            ("New executable", exec([:], ["executable_age_ms": 250]), exec([:], ["executable_age_ms": -5])),
            ("Ran a script", exec([:], ["script_content": "echo"]), exec([:], ["script_content": ""])),
            ("Reflective loading", file("CREATE", "create", 0, image), file("CREATE", "create", 0, "/tmp/x")),
            ("Unquarantined file created", file("CREATE", "create", 0, "/Users/a/Downloads/a.app", archiver),
             file("CREATE", "create", 0, "/private/var/folders/T/a.app", archiver)),
            ("Unquarantined file created", file("CREATE", "create", 0, "/Users/a/x", optIn),
             file("CREATE", "create", 0, image, optIn)),
            ("Quarantined file", file("CREATE", "create", 1, "/Users/a/x"), file("CREATE", "create", 1, image)),
            ("AppleScript / JXA", event("MMAP", ["target_path": "/System/Library/ScriptingAdditions/a.osax/a"]),
             event("MMAP", ["target_path": "/usr/lib/libSystem.B.dylib"])),
            ("Quarantined file renamed", file("RENAME", "rename", 1, "/Users/a/x"),
             file("RENAME", "rename", 0, "/Users/a/x")),
            ("Unquarantined app bundle", file("RENAME", "rename", 0, "/Applications/X.app"),
             file("RENAME", "rename", 1, "/Applications/X.app")),
            ("BTM database modified", file("RENAME", "rename", 0, btm + "/BackgroundItems-v13.btm"),
             file("RENAME", "rename", 1, btm + "/BackgroundItems-v13.btm")),
            ("Quarantine removed",
             event("DELETEEXTATTR", ["event": ["deleteextattr": ["extattr": "com.apple.quarantine"]]]),
             event("DELETEEXTATTR", ["event": ["deleteextattr": ["extattr": "com.apple.quarantine.x"]]])),
            ("Login Item written", event("WRITE", ["target_path": "/private/var/folders/backgroundtaskmanagementd/a"]),
             event("WRITE", ["target_path": btm + "/BackgroundItems-v13.btm"])),
            ("Background item added", event("BTM_LAUNCH_ITEM_ADD"), event("BTM_LAUNCH_ITEM_REMOVE")),
            ("Background item removed", event("BTM_LAUNCH_ITEM_REMOVE"), event("BTM_LAUNCH_ITEM_ADD")),
            ("XProtect detection", event("XP_MALWARE_REMEDIATED"), event("MOUNT")),
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

    /// Each built-in mark matches the event its label marked, and not a near miss, and so does each default that
    /// replaced a mark in 3.1.0, which marks the tables.
    func testEachMatchesItsLabelsEvent() throws {
        for (name, matching, other) in cases {
            let indicator = try XCTUnwrap((Indicator.builtInMarks + Indicator.defaults).first { $0.name == name }, name)
            XCTAssertTrue(!indicator.tableMarks.isEmpty && indicator.isEnabled, name)
            let predicate = try StreamFilter.Predicate(indicator.predicate, for: .indicator)
            XCTAssertTrue(try predicate.evaluate(on: matching), name)
            XCTAssertFalse(try predicate.evaluate(on: other), name)
        }
    }

    /// One key path compares with another, on a record and on the stored event alike.
    func testKeyPathComparesWithKeyPath() throws {
        let source = "event.exec.dyld_exec_path != event.exec.target.executable.path"
        let predicate = try StreamFilter.Predicate(source, for: .indicator)
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
        let names = ["Dylib inserted", "Root user", "Unquarantined file created"]
        let indicators = Indicator.builtInMarks.filter { names.contains($0.name) }
        for indicator in indicators {
            let predicate = try StreamFilter.Predicate(indicator.predicate, for: .indicator)
            XCTAssertTrue(StoredEventValues.canEvaluate(predicate.parsed), indicator.name)
        }
        try withEventStore([execMessage, create]) { _, stored in
            let found = Set(stored.flatMap { IndicatorMatcher(indicators).matches($0).map(\.name) })
            XCTAssertEqual(found, Set(names))
        }
    }

    /// Each built-in mark has its own identity and keeps its number. Each default with a twin shares its name,
    /// predicate and symbol.
    func testBuiltInMarksKeepTheirNumbers() throws {
        let twins = Indicator.builtInMarks.filter { mark in Indicator.defaults.contains { $0.id == mark.id } }
        XCTAssertEqual(Set(Indicator.builtInMarks.map(\.id)).count, Indicator.builtInMarks.count)
        XCTAssertEqual(Indicator.builtInMarks.count, 13)
        XCTAssertEqual(Set(twins.map(\.name)), ["New executable", "Ran a script", "Dylib inserted"])
        /// 18, 32 and 33 were the dyld exec path mismatch and the adhoc and unsigned warnings, now removed. 17 was the
        /// dyld injection mark, now the Dylib inserted indicator's twin (50). The marks with the numbers 16 and 25 to
        /// 30 became the defaults with those numbers in 3.1.0, and those 34 and 36 to 39 replaced were retired.
        XCTAssertEqual(Set(Indicator.builtInMarks.map(\.id)),
                       Set([9, 11, 15, 19, 20, 21, 22, 23, 24, 31, 35, 40, 50].map(Indicator.uuid)))
        XCTAssertTrue(Set([16, 25, 26, 27, 28, 29, 30].map(Indicator.uuid)).isSubset(of: Indicator.defaults.map(\.id)))
        for twin in twins {
            let indicator = try XCTUnwrap(Indicator.defaults.first { $0.id == twin.id })
            XCTAssertEqual([twin.predicate, twin.symbol, twin.name],
                           [indicator.predicate, indicator.symbol, indicator.name])
        }
    }

    /// Every default with a twin mark and that mark select the same events, so searching for the indicator finds the
    /// rows its mark is drawn on. It's checked on each label's event and near miss, the synthetic corpus and the
    /// lineage fixture, as records and as stored events.
    func testEachTwinSelectsItsDefaultsEvents() throws {
        let twins = Indicator.builtInMarks.compactMap { mark in
            Indicator.defaults.first { $0.id == mark.id }.map { (indicator: $0, mark: mark) }
        }
        XCTAssertEqual(twins.count, 3)
        let crafted = cases.flatMap { [$0.1, $0.2] }
        try withEventStore(try SyntheticCorpus.records().map(\.message) + (try lineageTrace())) { _, stored in
            let records = try stored.map { event in
                try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(event)) as? NSDictionary)
            } + crafted
            for (indicator, mark) in twins {
                let found = try StreamFilter.Predicate(indicator.predicate, for: .indicator)
                let marked = try StreamFilter.Predicate(mark.predicate, for: .indicator)
                for record in records {
                    XCTAssertEqual(try found.evaluate(on: record), try marked.evaluate(on: record), indicator.name)
                }
                for event in stored {
                    XCTAssertEqual(IndicatorMatcher([indicator]).matches(event).isEmpty,
                                   IndicatorMatcher([mark]).matches(event).isEmpty, indicator.name)
                }
            }
        }
    }

    /// New executable means one thing everywhere: the indicator, its mark, Event Facts' orange clock and Event Search's
    /// starter search all select an exec whose executable was created less than a second before it ran.
    func testNewExecutableAgreesEverywhere() throws {
        let indicator = try XCTUnwrap(Indicator.defaults.first { $0.name == "New executable" })
        let mark = try XCTUnwrap(Indicator.labelMarks.first { $0.id == indicator.id })
        XCTAssertEqual(indicator.predicate, Indicator.newExecutablePredicate)
        XCTAssertEqual(ESProcessExecEvent.newExecutableAge, 1)
        let base = try XCTUnwrap(SyntheticCorpus.records().first { $0.label == "exec (full)" }?.message)
        let ages = [-5, 0, 999, 1_000, 299_999, 300_000]
        let messages = try ages.map { age in
            var message = base
            guard case .exec(var exec) = message.event else { throw XCTSkip("not an exec") }
            exec.executable_age_ms = age
            message.event = .exec(exec)
            return message
        }
        try withEventStore(messages) { _, stored in
            for (age, event) in zip(ages, stored) {
                let expected = age >= 0 && age < 1_000
                XCTAssertEqual(!IndicatorMatcher([indicator]).matches(event).isEmpty, expected, "\(age)")
                XCTAssertEqual(!IndicatorMatcher([mark]).matches(event).isEmpty, expected, "\(age)")
                XCTAssertEqual(event.event.exec?.isNewExecutable, expected, "\(age)")
            }
        }
    }

    /// An indicator that marks the tables and is a twin of a mark drawn beside it is drawn once, as the mark, unless
    /// its symbol changed. The rest are drawn.
    func testTwinsDrawOnce() throws {
        let script = try XCTUnwrap(Indicator.defaults.first { $0.name == "Ran a script" })
        let age = try XCTUnwrap(Indicator.defaults.first { $0.name == "New executable" })
        let mark = try XCTUnwrap(Indicator.labelMarks.first { $0.id == age.id })
        let own = Indicator(name: "Mine", description: "", symbol: "star", color: .red, predicate: "process.pid == 1",
                            tables: [.dot, .symbol])
        XCTAssertEqual(Indicator.drawn([age, script, own], besides: [mark]), [script, own])
        var changed = age
        changed.symbol = "clock"
        XCTAssertEqual(Indicator.drawn([changed], besides: [mark]), [changed])
        XCTAssertEqual(mark.color, age.color)
        XCTAssertEqual(mark.description, "Its executable was {age} old at exec.")
    }

    /// The dyld injection mark is the Dylib inserted indicator's twin: the same identity, symbol and predicate, so an
    /// event that matches both draws one symbol, and changing the indicator changes the mark.
    func testDylibInsertedIsTheDyldMarksTwin() throws {
        let indicator = try XCTUnwrap(Indicator.defaults.first { $0.name == "Dylib inserted" })
        let mark = try XCTUnwrap(Indicator.builtInMarks.first { $0.name == "Dylib inserted" })
        XCTAssertEqual(mark.id, indicator.id)
        XCTAssertEqual(mark.symbol, indicator.symbol)
        XCTAssertEqual(mark.predicate, indicator.predicate)
        XCTAssertTrue(indicator.showsInTables)
        XCTAssertEqual(Indicator.drawn([indicator], besides: [mark]), [])
        XCTAssertFalse(Indicator.builtInMarks.contains { $0.name == "DYLD_INSERT_LIBRARIES" })
    }

    /// Each place draws its own marks, as its label did. The process name draws root, which the Elevated to root
    /// indicator joins wherever the tables mark it. The event type's label draws the rest. Both draw the dyld injection
    /// mark.
    func testEachPlaceDrawsItsMarks() {
        let label = Set(Indicator.labelMarks.map(\.name))
        let name = Set(Indicator.nameMarks.map(\.name))
        XCTAssertEqual(label.intersection(name), ["Dylib inserted"])
        XCTAssertTrue(name.contains("Root user"))
        XCTAssertFalse(label.contains("Root user"))
    }
}
