//
//  XCTestCase+ContentWrites.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Writes named by their content
/// What the tests of an indicator that reads a modified close's `file_type` share: a close derived from one Mac Monitor
/// 3.1 recorded, a tool run to write a real file, and the check that the file's content is named as expected and its
/// write matches as expected, in the Security Extension and in Mac Monitor's own matching alike.
extension XCTestCase {
    /// The fixture the closes are derived from: say's modified close of its SQLite cache's `-shm` (as user 501), then
    /// a rename, as Mac Monitor 3.1 recorded them.
    static let closeFixture = "macmonitor-3.1-close-rename.jsonl"

    /// A close derived from the first one recorded in ``closeFixture``: the recorded record with its path, its file's
    /// type and, when one is given, its process's signature changed, read as File > Open Trace... reads it.
    ///
    /// - Parameters:
    ///   - path: The file closed.
    ///   - type: The type its content is named by, or `nil` when it wasn't read.
    ///   - modified: Was it written?
    ///   - process: The closing process's signing ID and whether it's a platform binary, or `nil` for say's.
    /// - Returns: The event.
    /// - Throws: The error reading the fixture or the derived record.
    func derivedClose(at path: String, type: String?, modified: Bool = true,
                      by process: (signingID: String, isPlatform: Bool)? = nil) throws -> Message {
        let lines = String(decoding: try fixture(Self.closeFixture), as: UTF8.self).split(separator: "\n")
        let line = try XCTUnwrap(lines.first)
        let record = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(line.utf8), options: .mutableContainers)
                                   as? NSMutableDictionary)
        record["target_path"] = path
        record["context"] = path
        record.setValue(path, forKeyPath: "event.close.target.path")
        record.setValue((path as NSString).lastPathComponent, forKeyPath: "event.close.target.name")
        record.setValue(modified, forKeyPath: "event.close.modified")
        record.setValue(type ?? NSNull(), forKeyPath: "event.close.file_type")
        if let process {
            record.setValue(process.signingID, forKeyPath: "process.signing_id")
            record.setValue(process.isPlatform, forKeyPath: "process.is_platform_binary")
        }
        return try TraceImporter.message(from: JSONSerialization.data(withJSONObject: record))
    }

    /// Check that the shipped indicators decide an event, the Security Extension's compiled set and Mac Monitor's own
    /// matching find the same ones, and one indicator matches it as expected.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - matches: Should the indicator match it?
    ///   - id: The indicator's identity.
    ///   - label: What the case is.
    /// - Throws: The error storing the event.
    func assertShippedMatch(_ message: Message, _ matches: Bool, id: UUID, _ label: String) throws {
        var values = MessageValueCache()
        let evaluation = Self.shippedIndicators.evaluate(message, values: &values)
        XCTAssertEqual(evaluation.undetermined, [], label)
        XCTAssertEqual(evaluation.hits.map(\.id), try matcherHits(message), label)
        XCTAssertEqual(evaluation.hits.contains { $0.id == id }, matches, label)
    }

    /// Check a file's content is named as expected, as a capture lane reads a modified close's file
    /// (``FileTypeReader``), and that its write matches an indicator as expected (``assertShippedMatch(_:_:id:_:)``).
    ///
    /// - Parameters:
    ///   - path: The file, as its close names it.
    ///   - info: The close's stat of it, else the file's own now.
    ///   - type: The type it should be named by.
    ///   - matches: Should its write match?
    ///   - id: The indicator's identity.
    ///   - label: What the case is.
    /// - Throws: The error reading the file's stat or deriving its close.
    func assertContentWrite(of path: String, stat info: stat? = nil, isNamed type: String?, matching matches: Bool,
                            id: UUID, _ label: String) throws {
        let read = FileTypeReader.fileType(at: path, stat: try info ?? fileStat(path), for: currentReader,
                                           volumes: LocalVolumes())
        XCTAssertEqual(read?.identifier, type, label)
        try assertShippedMatch(try derivedClose(at: path, type: read?.identifier), matches, id: id, label)
    }

    /// Run a tool and wait for it.
    ///
    /// - Parameters:
    ///   - tool: The tool's path.
    ///   - arguments: Its arguments.
    ///   - checking: Fail the test when it doesn't exit 0?
    /// - Returns: Its exit status.
    /// - Throws: The error launching it.
    @discardableResult
    func runTool(_ tool: String, _ arguments: [String], checking: Bool = true) throws -> Int32 {
        let process = Foundation.Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        if checking { XCTAssertEqual(process.terminationStatus, 0, "\(tool) \(arguments)") }
        return process.terminationStatus
    }
}
