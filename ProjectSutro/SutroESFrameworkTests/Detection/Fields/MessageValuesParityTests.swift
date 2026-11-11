//
//  MessageValuesParityTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Parity with the record
/// Pins ``MessageValues`` to the record: every field's value on an event is the one a predicate on its record compares
/// (`ESMessage(from:)` encoded, read as ``PredicateRecord`` reads it), on every event Mac Monitor's tests have, and in
/// each case where the store writes something the event doesn't have.
final class MessageValuesParityTests: XCTestCase {
    /// Every field, on every event of the synthetic corpus, the fixtures and the lineage trace, is the record's, and
    /// each field has a value on some event, of its kind.
    func testValuesAreTheRecords() throws {
        let messages = try SyntheticCorpus.records().map(\.message) + allFixtureMessages() + lineageTrace()
        let found = try assertParity(messages)
        for field in IndicatorField.allCases {
            XCTAssertGreaterThan(found[field] ?? 0, 0, "\(field.path) has no value on any event")
        }
    }

    /// Every field, on every event the macath harnesses recorded on macOS 27, is the record's. They live in the
    /// macath repository, beside Mac Monitor's checkout or where `SUTRO_MACATH_RUNS` names, and the test is skipped
    /// without them.
    func testValuesAreTheMacathRecords() throws {
        let recordings = try macathRecordings()
        var events = 0
        for recording in recordings {
            let lines = String(decoding: try Data(contentsOf: recording), as: UTF8.self).split(separator: "\n")
            let messages = try lines.map { try importRecord(String($0)) }
            try assertParity(messages, in: recording.lastPathComponent)
            events += messages.count
        }
        XCTAssertGreaterThan(events, 1_000)
    }

    /// Every field, on the resolver connects `macmonitor stream` recorded on macOS 27
    /// (`Fixtures/macmonitor-3.1-resolver.jsonl`), is the record's: the socket's owner, the XPC service and its domain,
    /// and the adhoc flag of the process connecting each have a value there.
    func testValuesAreTheResolverRecords() throws {
        let found = try assertParity(try fixtureMessages("macmonitor-3.1-resolver.jsonl"))
        XCTAssertEqual(found[.uipcConnectFileStatUID], 3)
        XCTAssertEqual(found[.xpcConnectServiceName], 1)
        XCTAssertEqual(found[.xpcConnectServiceDomainTypeString], 1)
        XCTAssertEqual(found[.processIsAdhocSigned], 4)
    }

    /// An event without a context or a target path reads "Not supported" for each, as the store writes them.
    func testMissingContextAndTargetPathAreNotSupported() throws {
        var message = try corpusMessage("ES_EVENT_TYPE_NOTIFY_CLOSE")
        message.context = nil
        message.target_path = nil
        try assertValue(.context, of: message, is: IndicatorValue("Not supported"))
        try assertValue(.targetPath, of: message, is: IndicatorValue("Not supported"))
    }

    /// An exec without a command line reads "", never `nil`.
    func testMissingCommandLineIsEmpty() throws {
        let message = try exec { $0.command_line = nil }
        try assertValue(.execCommandLine, of: message, is: IndicatorValue(""))
    }

    /// A process without an executable reads "" for its code signing type, which the store keeps only beside one, and
    /// `nil` for its executable's path and name: the initiating process's and an exec target's.
    func testCodesigningTypeWithoutAnExecutableIsEmpty() throws {
        var message = try exec { $0.target.executable = nil }
        message.process.executable = nil
        for field in [IndicatorField.processCodesigningType, .execTargetCodesigningType] {
            try assertValue(field, of: message, is: IndicatorValue(""))
        }
        for field in [IndicatorField.processExecutablePath, .processExecutableName, .execTargetExecutablePath,
                      .execTargetExecutableName] {
            try assertValue(field, of: message, is: .null)
        }
    }

    /// "" for a code signing type only where its process is there: an exec target's is `nil` on any other event, as
    /// every field of another event type is.
    func testFieldsOfAnotherEventAreNil() throws {
        let close = try corpusMessage("ES_EVENT_TYPE_NOTIFY_CLOSE")
        let execFields = IndicatorField.allCases.filter { $0.path.hasPrefix("event.exec.") }
        XCTAssertEqual(execFields.count, 13)
        for field in execFields {
            try assertValue(field, of: close, is: .null)
        }
        let exec = try exec { _ in }
        for field in [IndicatorField.closeModified, .closeFileType, .closeMachOType, .deleteextattrExtattr,
                      .iokitOpenDriverBundleID, .uipcConnectFileStatUID, .xpcConnectServiceName,
                      .xpcConnectServiceDomainTypeString] {
            try assertValue(field, of: exec, is: .null)
        }
    }

    /// An exec target's user IDs and an IOKit open's user client class, which 3.1.0's Elevated to root and HID device
    /// opened read, are the record's, and the Security Extension's compiled set matches each on them as Mac Monitor's
    /// own matching does.
    func testUserIDsAndUserClientClass() throws {
        let elevated = try exec { $0.target.euid = 0; $0.target.ruid = 501 }
        try assertValue(.execTargetEUID, of: elevated, is: IndicatorValue(0))
        try assertValue(.execTargetRUID, of: elevated, is: IndicatorValue(501))
        try assertShippedMatch(elevated, true, id: shippedID("Elevated to root"), "sudo")
        try assertShippedMatch(try exec { $0.target.euid = 0; $0.target.ruid = 0 }, false,
                               id: shippedID("Elevated to root"), "root already")
        var open = try corpusMessage("ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN")
        guard case .iokit_open(var event) = open.event else { return XCTFail("Not an IOKit open") }
        for (userClient, matches) in [("IOHIDLibUserClient", true), ("IOSurfaceRootUserClient", false)] {
            event.user_client_class = userClient
            open.event = .iokit_open(event)
            try assertValue(.iokitOpenUserClientClass, of: open, is: IndicatorValue(userClient))
            try assertShippedMatch(open, matches, id: shippedID("HID device opened"), userClient)
        }
    }

    /// A create's quarantine state and its process's File Quarantine type, which 3.1.0's Unquarantined file from a
    /// File Quarantine-aware app reads, are the record's, and the Security Extension's compiled set matches on them as
    /// Mac Monitor's own matching does: a file an aware process leaves unquarantined, but not one in an `X` folder of
    /// `/private/var/folders`, a quarantined one, or one a process that isn't aware creates.
    func testQuarantineStateAndFileQuarantineType() throws {
        let folders = "/private/var/folders/by/997_b3mj46j5hy98rnfc28w00000gn"
        let cases: [(path: String, quarantined: Int16, type: FileQuarantineType, matches: Bool)] = [
            ("/Users/a/Downloads/x", 0, .optIn, true), ("/Users/a/Downloads/x", 0, .forced, true),
            ("/Users/a/Downloads/x", 1, .optIn, false), ("/Users/a/Downloads/x", 2, .optIn, false),
            ("/Users/a/Downloads/x", 0, .disabled, false),
            (folders + "/X/com.google.Chrome.code_sign_clone/code_sign_clone.lAVKBe", 0, .optIn, false),
            (folders + "/T/x", 0, .optIn, true),
        ]
        var create = try corpusMessage("ES_EVENT_TYPE_NOTIFY_CREATE")
        guard case .create(var event) = create.event else { return XCTFail("Not a create") }
        for (path, quarantined, type, matches) in cases {
            event.is_quarantined = quarantined
            create.event = .create(event)
            create.process.file_quarantine_type = type
            create.target_path = path
            try assertValue(.createIsQuarantined, of: create, is: IndicatorValue(Int(quarantined)))
            try assertValue(.processFileQuarantineType, of: create, is: IndicatorValue(type.rawValue))
            try assertShippedMatch(create, matches,
                                   id: shippedID("Unquarantined file from a File Quarantine-aware app"),
                                   "\(path), \(quarantined), \(type.rawValue)")
        }
    }

    /// A driver's bundle ID is read only from message version 10, as the store keeps it.
    func testDriverBundleIDNeedsVersion10() throws {
        var message = try corpusMessage("ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN")
        guard case .iokit_open(var open) = message.event else { return XCTFail("Not an IOKit open") }
        open.driver_bundle_id = "com.example.driver"
        message.event = .iokit_open(open)
        message.version = 10
        try assertValue(.iokitOpenDriverBundleID, of: message, is: IndicatorValue("com.example.driver"))
        message.version = 9
        try assertValue(.iokitOpenDriverBundleID, of: message, is: .null)
    }

    /// An executable's name is its path's last component, as `NSString` gives it, where the path ends in "/", is "/"
    /// or "", or puts a combining mark after its last "/".
    func testExecutableNamesAreLastPathComponents() throws {
        let names = ["/tmp/folder/": "folder", "/": "/", "": "", "launchctl": "launchctl",
                     "/usr/bin/\u{301}x": "\u{301}x",
                     "/Applications/Re\u{301}sume\u{301}.app": "Re\u{301}sume\u{301}.app"]
        for (path, name) in names {
            let message = try exec { $0.target.executable?.path = path }
            try assertValue(.execTargetExecutableName, of: message, is: IndicatorValue(name))
        }
    }
}


// MARK: - Checking parity
extension MessageValuesParityTests {
    /// Check every field's value on each event against its record.
    ///
    /// - Parameters:
    ///   - messages: The events.
    ///   - source: Where they're from, for failures.
    /// - Returns: How many events have a value for each field.
    /// - Throws: The error storing or encoding an event.
    @discardableResult
    func assertParity(_ messages: [Message], in source: String = "",
                      file: StaticString = #filePath, line: UInt = #line) throws -> [IndicatorField: Int] {
        let records = try records(of: messages)
        var found: [IndicatorField: Int] = [:]
        for (message, record) in zip(messages, records) {
            for field in IndicatorField.allCases {
                let object = record.value(forKeyPath: field.path)
                let expected = try XCTUnwrap(IndicatorValue(object: object),
                                             "\(field.path): \(String(describing: object))")
                let label = "\(source) \(message.es_event_type) \(field.path)"
                XCTAssertEqual(MessageValues.value(of: field, in: message), expected, label, file: file, line: line)
                guard !expected.isNull else { continue }
                found[field, default: 0] += 1
                XCTAssertEqual(Self.kind(of: object), field.kind, label, file: file, line: line)
            }
        }
        return found
    }

    /// Check one field's value on an event, and that its record has the same.
    ///
    /// - Parameters:
    ///   - field: The field.
    ///   - message: The event.
    ///   - expected: The value it should have.
    /// - Throws: The error storing or encoding the event.
    func assertValue(_ field: IndicatorField, of message: Message, is expected: IndicatorValue,
                     file: StaticString = #filePath, line: UInt = #line) throws {
        let record = try XCTUnwrap(records(of: [message]).first)
        XCTAssertEqual(MessageValues.value(of: field, in: message), expected, field.path, file: file, line: line)
        XCTAssertEqual(IndicatorValue(object: record.value(forKeyPath: field.path)), expected,
                       "\(field.path) in the record", file: file, line: line)
    }

    /// - Parameter messages: Events.
    /// - Returns: Their records, as a predicate reads them: each stored as Mac Monitor stores it, then encoded.
    /// - Throws: The error storing or encoding an event.
    func records(of messages: [Message]) throws -> [PredicateRecord] {
        try withEventStore(messages) { _, stored in
            try stored.map { event in
                PredicateRecord(try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(event))
                                              as? NSDictionary))
            }
        }
    }

    /// - Parameter object: A record's value.
    /// - Returns: The kind of field that holds it, or `nil` for any other value.
    static func kind(of object: Any?) -> IndicatorField.Kind? {
        switch object {
        case is String: .string
        case let number as NSNumber where CFGetTypeID(number) == CFBooleanGetTypeID(): .boolean
        case is NSNumber: .number
        case is [String]: .strings
        default: nil
        }
    }
}


// MARK: - Events
extension MessageValuesParityTests {
    /// - Parameter type: An event type's name, as in `ES_EVENT_TYPE_NOTIFY_CLOSE`.
    /// - Returns: The synthetic corpus's first event of that type.
    /// - Throws: The error making up the corpus, or a failure when it has no such event.
    func corpusMessage(_ type: String) throws -> Message {
        try XCTUnwrap(SyntheticCorpus.records().map(\.message).first { $0.es_event_type == type }, type)
    }

    /// - Parameter change: Changes the exec.
    /// - Returns: The synthetic corpus's first exec, changed.
    /// - Throws: The error making up the corpus, or a failure when it has no exec.
    func exec(_ change: (inout ProcessExecEvent) -> Void) throws -> Message {
        var message = try corpusMessage("ES_EVENT_TYPE_NOTIFY_EXEC")
        var exec = try XCTUnwrap(message.event.exec, "The corpus's first exec has no exec event")
        change(&exec)
        message.event = .exec(exec)
        return message
    }
}
