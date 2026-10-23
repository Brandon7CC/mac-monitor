//
//  XCTestCase+Wire.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Events on the wire
extension XCTestCase {
    /// The JSONL fixtures of real events: eslogger's on macOS 27, and Mac Monitor 2.1's export.
    static let eventFixtures = ["eslogger-exit.jsonl", "eslogger-open.jsonl", "eslogger-od.jsonl",
                                "eslogger-remote-thread-create.jsonl", "macmonitor-2.1-exit.jsonl"]
    
    /// Every record in a JSONL fixture, read as File > Open Trace… reads it.
    ///
    /// - Parameter name: The fixture's file name.
    /// - Returns: The events, in file order.
    /// - Throws: The error reading the fixture or a record.
    func fixtureMessages(_ name: String) throws -> [Message] {
        try String(decoding: try fixture(name), as: UTF8.self).split(separator: "\n").map { line in
            try importRecord(String(line))
        }
    }
    
    /// Every event in every JSONL fixture.
    ///
    /// - Returns: The events.
    /// - Throws: The error reading a fixture or a record.
    func allFixtureMessages() throws -> [Message] {
        try Self.eventFixtures.flatMap(fixtureMessages)
    }
    
    /// An event as the Security Extension sends it: a capture lane's streaming encoder's JSON.
    ///
    /// - Parameter message: The event.
    /// - Returns: The wire JSON.
    /// - Throws: The error encoding it.
    func wire(_ message: Message) throws -> Data {
        try StreamingJSONEncoder().encode(message)
    }
}
