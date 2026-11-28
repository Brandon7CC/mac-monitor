//
//  ExecWhereFromsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/27/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Where the program an exec runs was downloaded from
/// Pins an exec's `where_froms`: it's the script's, else its bundle's, else the executable's, else its bundle's, a
/// script's is read only from the file read for its text, an executable in the system folders isn't read, the schema
/// has it as an optional enrichment, it reads back from a trace, the app's store and an export as it was, and an
/// indicator reads it.
final class ExecWhereFromsTests: XCTestCase {
    /// A download URL and the page it was found on, as a browser writes them.
    static let origins = ["https://example.com/files/tool.zip?token=abc", "https://example.com/downloads"]
    /// Another download's.
    static let otherOrigins = ["https://example.org/setup"]

    /// The schema has `event.exec.where_froms` as Mac Monitor's own optional array of strings, which a rule compares.
    func testTheSchemaHasIt() throws {
        let root = try jsonObject(try TelemetrySchema.data())
        let exec = try XCTUnwrap(root[path: "$defs", "exec_event"] as? [String: Any])
        let key = try XCTUnwrap(exec[path: "properties", "where_froms"] as? [String: Any])
        XCTAssertEqual(key["type"] as? String, "array")
        XCTAssertEqual(key[path: "items", "type"] as? String, "string")
        XCTAssertEqual(key["x-mac-monitor-origin"] as? String, "mac-monitor")
        XCTAssertFalse((exec["required"] as? [String] ?? []).contains("where_froms"))
        XCTAssertEqual(RecordSchema.lookup("event.exec.where_froms"), .kind(.strings))
    }

    /// An exec's origins read back from its record, are kept by the app's store, and export as they were. One without
    /// any exports no key.
    func testItTravelsThroughTheStoreAndExports() throws {
        let message = try TraceImporter.message(from: try execRecord(Self.origins))
        XCTAssertEqual(message.event.exec?.where_froms, Self.origins)
        withStoredEvent(message) { stored in
            XCTAssertEqual(stored.event.exec?.where_froms, Self.origins)
        }
        XCTAssertEqual(try event("exec", in: try export(message))["where_froms"] as? [String], Self.origins)

        let plain = try TraceImporter.message(from: try execRecord(nil))
        XCTAssertNil(plain.event.exec?.where_froms)
        XCTAssertNil(try event("exec", in: try export(plain))["where_froms"])
    }

    /// A rule on an exec's origins reads them with `ANY`, and doesn't match an exec without any.
    func testAnIndicatorReadsIt() throws {
        let rule = ownIndicator("Downloaded from example.com",
                                #"event.exec != nil AND ANY event.exec.where_froms BEGINSWITH "https://example.com/""#)
        let indicators = CompiledIndicators([rule])
        XCTAssertEqual(indicators.problems.map(\.reason), [])
        var values = MessageValueCache()
        for (origins, hits) in [(Self.origins, [rule.id]), (Self.otherOrigins, []), (nil, [])] {
            let message = try TraceImporter.message(from: try execRecord(origins))
            XCTAssertEqual(indicators.evaluate(message, values: &values).hits.map(\.id), hits, "\(origins ?? [])")
        }
    }

    /// The script an exec runs gives its origins, whether Endpoint Security names it (`./tool.sh`) or an interpreter's
    /// arguments do (`bash tool.sh`), and they come before the executable's.
    func testTheScriptsOriginsAreRead() throws {
        let directory = try makeTemporaryDirectory()
        let script = try writeFile("tool.sh", "#!/bin/bash\necho tool\n", in: directory, origins: Self.origins)
        let executable = try writeFile("interpreter", "#!/bin/sh\n", in: directory, origins: Self.otherOrigins)

        XCTAssertEqual(read(try exec(executable, args: [executable, script], in: directory.path, script: script)),
                       Self.origins)
        XCTAssertEqual(read(try exec("/bin/bash", args: ["/bin/bash", "tool.sh"], in: directory.path)), Self.origins)
    }

    /// A script without origins falls back to the executable's, and the executable to the bundle it's the main
    /// executable of. A list with no strings counts as none.
    func testTheExecutablesThenTheBundlesOriginsAreRead() throws {
        let directory = try makeTemporaryDirectory()
        let script = try writeFile("tool.sh", "echo tool\n", in: directory, origins: nil)
        let tool = try writeFile("tool", "#!/bin/sh\n", in: directory, origins: Self.otherOrigins)
        XCTAssertEqual(read(try exec(tool, args: [tool, script], in: directory.path, script: script)),
                       Self.otherOrigins)

        let bundle = try makeBundle(in: directory)
        let helper = bundle + "/Contents/MacOS/Helper"
        try setWhereFroms(Self.origins, on: bundle)
        XCTAssertEqual(read(try exec(helper, args: [helper], in: directory.path)), Self.origins)
        try setWhereFroms([], on: helper)
        XCTAssertEqual(read(try exec(helper, args: [helper], in: directory.path)), Self.origins)
        try setWhereFroms(Self.otherOrigins, on: helper)
        XCTAssertEqual(read(try exec(helper, args: [helper], in: directory.path)), Self.otherOrigins)
    }

    /// An app whose main executable is a shell script runs as its interpreter with the script: the script has no
    /// origins of its own when the app came in an archive, and the bundle's are read.
    func testAShellScriptAppsBundleOriginsAreRead() throws {
        let bundle = try makeBundle(in: try makeTemporaryDirectory())
        let helper = bundle + "/Contents/MacOS/Helper"
        try setWhereFroms(Self.origins, on: bundle)
        let directory = (bundle as NSString).deletingLastPathComponent
        XCTAssertEqual(read(try exec("/bin/sh", args: ["/bin/sh", helper], in: directory, script: helper)),
                       Self.origins)
        XCTAssertEqual(read(try exec("/bin/bash", args: ["/bin/bash", helper], in: directory)), Self.origins)
        try setWhereFroms(Self.otherOrigins, on: helper)
        XCTAssertEqual(read(try exec("/bin/bash", args: ["/bin/bash", helper], in: directory)), Self.otherOrigins)
    }

    /// A script the exec's user can't read isn't looked at, and an executable in the sealed system volume's folders
    /// isn't read. The Data volume's are, `/System/Volumes/Data` and `/usr/local` included.
    func testWhatIsntReadHasNone() throws {
        let directory = try makeTemporaryDirectory()
        let script = try writeFile("tool.sh", "echo tool\n", in: directory, origins: Self.origins)
        chmod(script, 0o600)
        let readers = [(FileReader(uid: 4_242, gid: 4_242), false), (FileReader(uid: getuid(), gid: getgid()), true)]
        for (reader, read) in readers {
            let result = ProcessExecEvent.readScript(reported: try file(script), args: ["/bin/sh", script],
                                                     workingDirectory: directory.path, interpreterName: "sh",
                                                     reader: reader)
            XCTAssertEqual(result.read?.whereFroms, read ? Self.origins : nil, "uid \(reader.uid)")
        }

        for path in ["/bin/ls", "/sbin/mount", "/usr/bin/curl", "/usr/sbin/sshd", "/usr/libexec/xpcproxy",
                     "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"] {
            XCTAssertTrue(ProcessHelpers.isInSystemFolder(path), path)
        }
        for path in ["/System/Volumes/Data/Users/a/tool", "/usr/local/bin/tool", "/Users/a/Downloads/tool",
                     "/Applications/Tool.app/Contents/MacOS/Tool", "/private/tmp/ls", "/usr/binary", script] {
            XCTAssertFalse(ProcessHelpers.isInSystemFolder(path), path)
        }
        XCTAssertNil(ProcessHelpers.whereFroms(ofExecutable: File(path: "/bin/ls")))
        XCTAssertEqual(ProcessHelpers.whereFroms(ofExecutable: try file(script)), Self.origins)
    }

    /// An open file's origins are read from its descriptor: none without the attribute, for a value that isn't a
    /// list, or for a list with no strings.
    func testADescriptorsOriginsAreRead() throws {
        let directory = try makeTemporaryDirectory()
        let path = try writeFile("tool.sh", "echo tool\n", in: directory, origins: Self.origins)
        let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
        defer { try? handle.close() }
        XCTAssertEqual(ProcessHelpers.whereFroms(of: handle.fileDescriptor), Self.origins)
        try setWhereFroms([], on: path)
        XCTAssertNil(ProcessHelpers.whereFroms(of: handle.fileDescriptor))
        let text = Array("https://example.com".utf8)
        XCTAssertEqual(setxattr(path, ProcessHelpers.whereFromsAttribute, text, text.count, 0, 0), 0, errnoText())
        XCTAssertNil(ProcessHelpers.whereFroms(of: handle.fileDescriptor))
        XCTAssertEqual(removexattr(path, ProcessHelpers.whereFromsAttribute, 0), 0, errnoText())
        XCTAssertNil(ProcessHelpers.whereFroms(of: handle.fileDescriptor))
    }
}


// MARK: - Helpers
extension ExecWhereFromsTests {
    /// The synthetic corpus's full exec with some origins or none, as Export telemetry writes its record.
    ///
    /// - Parameter origins: Its `where_froms`.
    /// - Returns: The record and a newline.
    /// - Throws: The error making up the corpus, or a failure when it has no exec.
    private func execRecord(_ origins: [String]?) throws -> Data {
        var message = try XCTUnwrap(SyntheticCorpus.records().map(\.message)
            .first { $0.es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" })
        var exec = try XCTUnwrap(message.event.exec)
        exec.where_froms = origins
        message.event = .exec(exec)
        return ExportEncoder(model: try XCTUnwrap(ExportEncoder.model)).line(for: message)
    }

    /// An exec whose target runs an executable with arguments in a directory, with its script read as the capture
    /// lane reads it.
    ///
    /// - Parameters:
    ///   - executable: The target's executable.
    ///   - args: Its arguments.
    ///   - directory: Its working directory.
    ///   - script: The script Endpoint Security names, or `nil`.
    /// - Returns: The exec.
    /// - Throws: The error reading its record or a file's stat.
    private func exec(_ executable: String, args: [String], in directory: String,
                      script: String? = nil) throws -> ProcessExecEvent {
        var exec = try XCTUnwrap(try importRecord(try esloggerExec(parent: (1, 1), args: args)).event.exec)
        exec.target.executable = try file(executable)
        exec.cwd = try file(directory)
        exec.script = try script.map(file)
        return exec
    }

    /// Where an exec's program was downloaded from, read as the capture lane reads it.
    ///
    /// - Parameter exec: The exec.
    /// - Returns: Its `where_froms`.
    private func read(_ exec: ProcessExecEvent) -> [String]? {
        var exec = exec
        exec.readScript()
        exec.readWhereFroms()
        return exec.where_froms
    }

    /// A file as Endpoint Security names one.
    ///
    /// - Parameter path: Its path.
    /// - Returns: The file, with its stat.
    /// - Throws: The error reading its stat.
    private func file(_ path: String) throws -> File {
        var file = File(path: path)
        file.stat = Stat(from: try fileStat(path))
        return file
    }

    /// Write a file, with some origins or none.
    ///
    /// - Parameters:
    ///   - name: Its name.
    ///   - text: Its text.
    ///   - directory: Where it goes.
    ///   - origins: Its `com.apple.metadata:kMDItemWhereFroms`, or `nil` for none.
    /// - Returns: Its path.
    /// - Throws: The error writing it.
    private func writeFile(_ name: String, _ text: String, in directory: URL, origins: [String]?) throws -> String {
        let url = directory.appendingPathComponent(name)
        try Data(text.utf8).write(to: url)
        chmod(url.path, 0o755)
        if let origins { try setWhereFroms(origins, on: url.path) }
        return url.path
    }
}
