//
//  AppleScriptWrittenIndicatorTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - AppleScript written
/// Pins AppleScript written on scripts macOS 27's own tools write: each is read as a capture lane reads a modified
/// close's file (``FileTypeReader``), and the type it's named by is set on a close derived from one `macmonitor
/// stream` recorded. The Security Extension's compiled set and Mac Monitor's own matching agree on every one and
/// leave none undetermined, a match is stamped as a shipped low indicator, and the rule is looked up by the file's
/// type alone, so no other close is evaluated against it.
///
/// `osacompile` writes AppleScript as `FasdUAS` and JXA as `JsOsaDAS`, as a `.scpt`, a script bundle's or an applet's
/// `main.scpt`, run-only or not, and `store script` writes the same. Text AppleScript is AppleScript by its content
/// when its `#!` line names osascript, and text without one, whatever its name.
final class AppleScriptWrittenIndicatorTests: XCTestCase {
    /// The indicator's name.
    private static let name = "AppleScript written"
    /// AppleScript that sets a property, so osascript saves it back into the script after running it.
    private static let appleScript = "property runs : 0\nset runs to runs + 1\nreturn runs\n"
    /// JXA that returns a value.
    private static let javaScript = "var runs = 1; runs\n"

    /// A script `osacompile` writes, and where its compiled script is.
    private struct Compiled {
        /// What the case is.
        let label: String
        /// The output's name.
        let output: String
        /// `osacompile`'s options before `-o`.
        let options: [String]
        /// The compiled script's path in the output, or empty for the output itself.
        let script: String
    }

    /// The scripts `osacompile` writes: AppleScript and JXA, plain, run-only, a script bundle and an applet, and one
    /// named `.txt`.
    private static let compiled: [Compiled] = {
        let main = "/Contents/Resources/Scripts/main.scpt"
        return [
            Compiled(label: "AppleScript", output: "run.scpt", options: [], script: ""),
            Compiled(label: "run-only AppleScript", output: "run-only.scpt", options: ["-x"], script: ""),
            Compiled(label: "script bundle", output: "Bundle.scptd", options: [], script: main),
            Compiled(label: "applet", output: "Login.app", options: [], script: main),
            Compiled(label: "run-only applet", output: "Hidden.app", options: ["-x"], script: main),
            Compiled(label: "AppleScript named .txt", output: "notes.txt", options: [], script: ""),
            Compiled(label: "JXA", output: "jxa.scpt", options: ["-l", "JavaScript"], script: ""),
            Compiled(label: "run-only JXA", output: "jxa-run-only.scpt", options: ["-l", "JavaScript", "-x"],
                     script: ""),
            Compiled(label: "JXA applet", output: "JXA.app", options: ["-l", "JavaScript"], script: main),
        ]
    }()

    /// Each script `osacompile` writes is named a compiled script by its content, and AppleScript written matches it,
    /// in the extension and in the app alike, with every indicator decided.
    func testCompiledScriptsMatch() throws {
        let id = try shippedID(Self.name)
        let folder = try resolvedTemporaryDirectory()
        let source = try sources(in: folder)
        for compiled in Self.compiled {
            let output = folder + "/" + compiled.output
            let input = compiled.options.contains("JavaScript") ? source.javaScript : source.appleScript
            try runTool("/usr/bin/osacompile", compiled.options + ["-o", output, input])
            try assertContentWrite(of: output + compiled.script, isNamed: FileType.compiledAppleScript.identifier,
                                   matching: true, id: id, compiled.label)
        }
    }

    /// Text AppleScript whose `#!` line names osascript is AppleScript by its content, named or not, and matches, but a
    /// JXA one is JavaScript, as node's are, and doesn't.
    func testOsascriptScriptsByTheirLine() throws {
        let id = try shippedID(Self.name)
        let script = try temporaryFile(bytes: Array(("#!/usr/bin/osascript\n" + Self.appleScript).utf8), named: "sync",
                                       mode: 0o755)
        try assertContentWrite(of: script, isNamed: FileType.appleScriptText.identifier, matching: true, id: id,
                               "#!/usr/bin/osascript")
        try runTool(script, [])
        let jxa = try temporaryFile(bytes: Array(("#!/usr/bin/osascript -l JavaScript\n" + Self.javaScript).utf8),
                                    named: "jxa", mode: 0o755)
        try assertContentWrite(of: jxa, isNamed: "com.netscape.javascript-source", matching: false, id: id,
                               "#!/usr/bin/osascript -l JavaScript")
    }

    /// Text AppleScript without a `#!` line is text, named `.applescript` or `.scpt`, and doesn't match.
    func testTextScriptsDontMatch() throws {
        let id = try shippedID(Self.name)
        let source = try sources(in: try resolvedTemporaryDirectory())
        try assertContentWrite(of: source.appleScript, isNamed: "public.plain-text", matching: false, id: id,
                               ".applescript")
        let named = try temporaryFile(bytes: Array(Self.appleScript.utf8), named: "run.scpt")
        try assertContentWrite(of: named, isNamed: "public.plain-text", matching: false, id: id, "text named .scpt")
    }

    /// osascript writes a compiled script with `store script`, here named `.txt`, and saves a script's properties
    /// back into it after running it, and each write matches.
    func testOsascriptWritesMatch() throws {
        let id = try shippedID(Self.name)
        let folder = try resolvedTemporaryDirectory()
        let source = try sources(in: folder)
        let stored = folder + "/stored.txt"
        let store = folder + "/store.applescript"
        try Data("script s\nreturn 1\nend script\nstore script s in POSIX file \"\(stored)\"\n".utf8)
            .write(to: URL(fileURLWithPath: store))
        try runTool("/usr/bin/osascript", [store])
        try assertContentWrite(of: stored, isNamed: FileType.compiledAppleScript.identifier, matching: true, id: id,
                               "store script")
        let script = folder + "/properties.scpt"
        try runTool("/usr/bin/osacompile", ["-o", script, source.appleScript])
        let before = try Data(contentsOf: URL(fileURLWithPath: script))
        try runTool("/usr/bin/osascript", [script])
        XCTAssertNotEqual(try Data(contentsOf: URL(fileURLWithPath: script)), before, "Its property wasn't saved")
        try assertContentWrite(of: script, isNamed: FileType.compiledAppleScript.identifier, matching: true, id: id,
                               "properties saved back")
    }

    /// Script Editor's and osacompile's writes match, as does a process that only calls itself backupd, but an
    /// unmodified close, Time Machine's copy and a close whose type wasn't read don't.
    func testWritersAndClosesDecide() throws {
        let id = try shippedID(Self.name)
        let script = FileType.compiledAppleScript.identifier
        let path = "/Users/marcus/Library/Scripts/run.scpt"
        let cases: [(String, Message, Bool)] = [
            ("Script Editor", try derivedClose(at: path, type: script, by: ("com.apple.ScriptEditor2", true)), true),
            ("osacompile", try derivedClose(at: path, type: script, by: ("com.apple.osacompile", true)), true),
            ("an unmodified close", try derivedClose(at: path, type: script, modified: false), false),
            ("Time Machine", try derivedClose(at: "/Volumes/Backups/run.scpt", type: script,
                                              by: (Indicator.backupd, true)), false),
            ("another backupd", try derivedClose(at: path, type: script, by: (Indicator.backupd, false)), true),
            ("no type", try derivedClose(at: path, type: nil), false),
        ]
        for (label, message, matches) in cases {
            try assertShippedMatch(message, matches, id: id, label)
        }
    }

    /// A write is stamped as the Security Extension stamps it: the indicator's name, low, Execution's T1059.002,
    /// shipped and unedited, and the verdict survives the wire.
    func testWriteIsStampedAsShippedLow() throws {
        let id = try shippedID(Self.name)
        var message = try derivedClose(at: "/Users/marcus/Library/Scripts/run.scpt",
                                       type: FileType.compiledAppleScript.identifier)
        var values = MessageValueCache()
        Self.shippedIndicators.stamp(&message, values: &values)
        let hit = try XCTUnwrap(message.indicators?.hits.first { $0.id == id })
        XCTAssertEqual(hit.name, Self.name)
        XCTAssertEqual(hit.severity, .low)
        XCTAssertEqual(hit.tactic_id, "TA0002")
        XCTAssertEqual(hit.technique, "T1059.002")
        XCTAssertTrue(hit.isDefault)
        XCTAssertFalse(hit.edited)
        assertStamped(message.indicators)
        XCTAssertEqual(try JSONDecoder().decode(Message.self, from: JSONEncoder().encode(message)).indicators,
                       message.indicators)
    }

    /// The rule runs on closes alone, where the index looks it up by the file's type, exactly, compiled or text: the
    /// recorded close of a database's `-shm`, which is data, never evaluates it.
    func testRuleIsAnchoredOnTheTypes() throws {
        let indicator = try XCTUnwrap(Indicator.defaults.first { $0.name == Self.name })
        XCTAssertEqual(indicator.id, Indicator.uuid(59))
        let rule = try IndicatorCompiler.compile(indicator.predicate).get()
        let close = Int(ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue)
        XCTAssertEqual(rule.types, [close])
        guard case .anyOf(let found) = rule.program.necessity(eventType: close) else {
            return XCTFail("Not anchored on closes")
        }
        let described = found.map { anchor in
            let bytes = rule.program.bytes[Int(anchor.offset)..<Int(anchor.offset + anchor.length)]
            return "\(anchor.field) \(anchor.shape) \(anchor.folding) \(String(decoding: bytes, as: UTF8.self))"
        }
        XCTAssertEqual(described, ["closeFileType exact false com.apple.applescript.script",
                                   "closeFileType exact false com.apple.applescript.text"])
        let alone = CompiledIndicators([indicator])
        var values = MessageValueCache()
        for message in try fixtureMessages(Self.closeFixture) {
            XCTAssertEqual(alone.candidates(for: message, values: &values), [], message.target_path ?? "")
        }
        for type in [FileType.compiledAppleScript, FileType.appleScriptText] {
            let script = try derivedClose(at: "/tmp/a", type: type.identifier)
            XCTAssertEqual(alone.candidates(for: script, values: &values), [0], type.identifier)
        }
    }

    // MARK: Sources
    /// Write the AppleScript and JXA the tests compile.
    ///
    /// - Parameter folder: Where to write them.
    /// - Returns: The AppleScript's path, named `.applescript`, and the JXA's, named `.js`.
    /// - Throws: The error writing them.
    private func sources(in folder: String) throws -> (appleScript: String, javaScript: String) {
        let paths = (appleScript: folder + "/run.applescript", javaScript: folder + "/run.js")
        try Data(Self.appleScript.utf8).write(to: URL(fileURLWithPath: paths.appleScript))
        try Data(Self.javaScript.utf8).write(to: URL(fileURLWithPath: paths.javaScript))
        return paths
    }
}
