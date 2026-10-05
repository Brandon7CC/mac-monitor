//
//  MuteCommandTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - macmonitor mute, end to end
/// Runs `macmonitor mute` end to end in one process: ``MuteCommand`` and ``StreamClient`` over a real NSXPC
/// connection to ``StreamService``, whose saved mute set is kept in a temporary directory.
final class MuteCommandTests: XCTestCase {
    private var savedMutes = SavedMuteSet(testing: MuteStore(directory: URL(fileURLWithPath: "/nonexistent")))
    
    /// A saved set in a fresh directory.
    ///
    /// - Throws: If the directory can't be created.
    override func setUpWithError() throws {
        try super.setUpWithError()
        savedMutes = SavedMuteSet(testing: try makeMuteStore())
    }
    
    /// Run one mute command and wait for it.
    ///
    /// - Parameters:
    ///   - invocation: The command.
    ///   - admits: Treat the caller as root?
    ///   - input: What standard input holds, for `import -`.
    ///   - confirm: Answers the question `import` and `reset` ask: by default there's no one to ask.
    /// - Returns: The result, standard output, and standard error's lines.
    private func run(_ invocation: MuteInvocation, admits: Bool = true, input: Data = Data(),
                     confirm: @escaping (String) -> Bool? = { _ in nil })
        -> (result: Result<Void, CommandLineFailure>?, output: String, errors: [String]) {
        let harness = StreamHarness(savedMutes: savedMutes, admits: admits)
        let client = StreamClient(connection: NSXPCConnection(listenerEndpoint: harness.endpoint), requirement: nil)
        client.activate(receiving: TestStreamReader()) { _ in }
        defer { client.invalidate() }
        let (output, errors) = (BufferOutput(), DiagnosticLines())
        let command = MuteCommand(client: client, output: output, diagnose: errors.append, confirm: confirm,
                                  readFile: { path in path == "-" ? input : try MuteCommand.readImport(path) },
                                  consoleUser: { .tester })
        let finished = expectation(description: "finished")
        var result: Result<Void, CommandLineFailure>?
        command.run(invocation) {
            result = $0
            finished.fulfill()
        }
        wait(for: [finished], timeout: 10)
        return (result, output.text, errors.all)
    }
    
    /// `list` shows the saved set, which starts as Mac Monitor's default set, one mute a line under a header.
    func testListShowsTheSavedSet() throws {
        let (result, output, errors) = run(.list())
        XCTAssertNoThrow(try result?.get())
        let lines = output.split(separator: "\n")
        XCTAssertEqual(lines.count, MuteList.testDefault.count + 1)
        XCTAssertTrue(lines.first?.hasPrefix("TYPE ") == true)
        XCTAssertEqual(errors, [])
    }
    
    /// `add` and `remove` change the saved set, say so, and say when there was nothing to do.
    func testAddAndRemove() throws {
        let entry = MuteFile.Entry(path: "/usr/bin/yes", type: "ES_MUTE_PATH_TYPE_LITERAL")
        let count = MuteList.testDefault.count
        XCTAssertEqual(run(.add(entry)).output, "Muted /usr/bin/yes (literal, every event). \(count + 1) mutes now.\n")
        XCTAssertEqual(run(.add(entry)).output,
                       "Already muted: /usr/bin/yes (literal, every event). \(count + 1) mutes now.\n")
        XCTAssertTrue(run(.list()).output.split(separator: "\n").contains {
            $0.hasPrefix("literal ") && $0.contains(" every event ") && $0.hasSuffix(" /usr/bin/yes")
        })
        XCTAssertEqual(run(.remove(entry)).output, "Unmuted /usr/bin/yes (literal, every event). \(count) mutes now.\n")
        XCTAssertEqual(run(.remove(entry)).output,
                       "Wasn't muted: /usr/bin/yes (literal, every event). \(count) mutes now.\n")
    }
    
    /// The Security Extension's warnings go to standard error, and its refusals end the command with their status.
    func testWarningsAndRefusals() {
        let unresolved = MuteFile.Entry(path: "/tmp/x", type: "ES_MUTE_PATH_TYPE_LITERAL")
        let added = run(.add(unresolved))
        XCTAssertNoThrow(try added.result?.get())
        XCTAssertEqual(added.errors.count, 1)
        XCTAssertTrue(added.errors.first?.contains("/private/tmp/x") == true)
        
        let narrowing = MuteFile.Entry(path: "/tmp/x", type: "ES_MUTE_PATH_TYPE_LITERAL",
                                       events: ["ES_EVENT_TYPE_NOTIFY_EXEC"])
        guard case .failure(let invalid)? = run(.remove(narrowing)).result else { return XCTFail("not refused") }
        XCTAssertEqual(invalid.exit, .dataError)
        
        guard case .failure(let notRoot)? = run(.reset(confirmed: true), admits: false).result else {
            return XCTFail("not refused")
        }
        XCTAssertEqual(notRoot.exit, .noPermission)
    }
    
    /// `export` writes exactly the saved file, as `list --format json` does; importing it back changes nothing, so it
    /// doesn't ask; `reset` restores the default.
    ///
    /// - Throws: The error writing the exported file.
    func testExportImportAndReset() throws {
        _ = run(.add(MuteFile.Entry(path: "/usr/bin/yes", type: "ES_MUTE_PATH_TYPE_PREFIX")))
        let exported = run(.export).output
        let expected = MuteFile(try MuteFile.decode(Data(exported.utf8)).list(.strict).list).encoded()
        XCTAssertEqual(exported, String(decoding: expected, as: UTF8.self))
        
        XCTAssertEqual(run(.list(format: .json)).output, exported)
        
        let file = try temporaryFile(containing: exported, named: "mutes.json")
        XCTAssertEqual(run(.importFile(path: file.path, merge: false)).output,
                       "The saved set already had them: \(MuteList.testDefault.count + 1) mutes now.\n")
        XCTAssertEqual(run(.importFile(path: "-", merge: false), input: Data(exported.utf8)).output,
                       "The saved set already had them: \(MuteList.testDefault.count + 1) mutes now.\n")
        let count = MuteList.testDefault.count
        XCTAssertEqual(run(.reset(confirmed: true)).output,
                       "The saved mute set is Mac Monitor's default set again: \(count) mutes.\n")
    }
    
    /// `import` and `reset` say what they'd change and ask first. With no one to ask they need `--yes` (64), and a no
    /// is 1, both leaving the saved set as it was; a yes goes ahead. A change that changes nothing isn't asked about.
    ///
    /// - Throws: The error writing the file to import.
    func testImportAndResetAskFirst() throws {
        let count = MuteList.testDefault.count
        _ = run(.add(MuteFile.Entry(path: "/usr/bin/yes", type: "ES_MUTE_PATH_TYPE_LITERAL")))
        guard case .failure(let unasked)? = run(.reset()).result else { return XCTFail("reset without asking") }
        XCTAssertEqual(unasked.exit, .usage)
        XCTAssertTrue(unasked.message.hasSuffix("Add --yes to go ahead."))
        guard case .failure(let declined)? = run(.reset(), confirm: { _ in false }).result else {
            return XCTFail("reset after a no")
        }
        XCTAssertEqual(declined, .declined)
        XCTAssertEqual(declined.exit.rawValue, 1)
        XCTAssertEqual(run(.list()).output.split(separator: "\n").count, count + 2)
        
        let questions = DiagnosticLines()
        XCTAssertNoThrow(try run(.reset()) { questions.append($0); return true }.result?.get())
        XCTAssertEqual(questions.all, ["""
            \(MuteCommand.PendingChange.reset(for: .tester).question)
            It adds 0 mutes, removes 1 and changes 0: \(count + 1) mutes now, \(count) after.
            \(MuteCommand.reach)
            """])
        XCTAssertNoThrow(try run(.reset()) { _ in XCTFail("asked about nothing"); return false }.result?.get())
        
        let yes = #"{"version":1,"mutes":[{"path":"/usr/bin/yes","type":"ES_MUTE_PATH_TYPE_LITERAL"}]}"#
        let file = try temporaryFile(containing: yes, named: "yes.json")
        XCTAssertNoThrow(try run(.importFile(path: file.path, merge: true)) { questions.append($0); return true }
            .result?.get())
        XCTAssertTrue(questions.all.last?.hasPrefix("""
            Add the mutes from “\(file.path)” to the saved mute set?
            It adds 1 mute, removes 0 and changes 0: \(count) mutes now, \(count + 1) after.
            """) == true)
        XCTAssertNoThrow(try run(.importFile(path: "-", merge: false), input: Data(yes.utf8)) {
            questions.append($0)
            return true
        }.result?.get())
        XCTAssertTrue(questions.all.last?.hasPrefix("""
            Replace the saved mute set with the mutes from standard input?
            It adds 0 mutes, removes \(count) and changes 0: \(count + 1) mutes now, 1 after.
            """) == true)
        XCTAssertEqual(run(.list()).output.split(separator: "\n").count, 2)
    }
    
    /// A saved set from a newer Mac Monitor is only reset after asking, with its notice said first, though the set
    /// applied now is already the default: a no keeps the newer file, and with no one to ask, `--yes` is needed.
    ///
    /// - Throws: The error writing the newer file.
    func testResettingANewerSavedSetAsksFirst() throws {
        let store = try makeMuteStore()
        try writeSavedFile(#"{"version": 2, "mutes": []}"#, in: store)
        let newer = savedFile(in: store)
        savedMutes = SavedMuteSet(testing: store)
        
        let questions = DiagnosticLines()
        let declined = run(.reset()) { questions.append($0); return false }
        guard case .failure(let failure)? = declined.result else { return XCTFail("reset without asking") }
        XCTAssertEqual(failure, .declined)
        let reset = MuteCommand.PendingChange.reset(for: .tester)
        XCTAssertEqual(questions.all, ["\(reset.question)\n\(MuteCommand.reach)"])
        XCTAssertEqual(declined.errors.count, 1)
        XCTAssertTrue(declined.errors.first?.contains("newer Mac Monitor (mute file version 2)") == true)
        XCTAssertEqual(savedFile(in: store), newer)
        
        guard case .failure(let unasked)? = run(.reset()).result else { return XCTFail("reset without asking") }
        XCTAssertEqual(unasked.exit, .usage)
        XCTAssertEqual(savedFile(in: store), newer)
    }
    
    /// A file with only Apple's AUTH mutes has nothing to import: each left-out entry is on standard error, and the
    /// saved set is unchanged (65). A file that can't be read is 66.
    ///
    /// - Throws: The error writing the file.
    func testImportsThatCantHappen() throws {
        let appleOnly = [
            #"{"path":"/usr/libexec/opendirectoryd","type":"ES_MUTE_PATH_TYPE_LITERAL","#
                + #""events":["ES_EVENT_TYPE_AUTH_OPEN"]}"#,
            #"{"path":"/usr/sbin/securityd","type":"ES_MUTE_PATH_TYPE_PREFIX","events":["ES_EVENT_TYPE_AUTH_EXEC"]}"#
        ].joined(separator: "\n")
        let file = try temporaryFile(containing: appleOnly, named: "apple.json")
        let apple = run(.importFile(path: file.path, merge: false))
        guard case .failure(let empty)? = apple.result else { return XCTFail("imported") }
        XCTAssertEqual(empty.exit, .dataError)
        XCTAssertEqual(apple.errors.count, 2)
        XCTAssertEqual(run(.list()).output.split(separator: "\n").count, MuteList.testDefault.count + 1)
        
        for path in ["/nonexistent/mutes.json", try makeTemporaryDirectory().path] {
            guard case .failure(let unreadable)? = run(.importFile(path: path, merge: true)).result else {
                return XCTFail(path)
            }
            XCTAssertEqual(unreadable.exit, .noInput, path)
        }
    }
    
    /// The table: types and events by the names `mute add` takes, every path escaped.
    func testTheTable() {
        XCTAssertEqual(MuteTable.text([]), "The saved mute set is empty.\n")
        let text = MuteTable.text([
            MuteFile.Entry(path: "/usr/libexec/logd", type: "ES_MUTE_PATH_TYPE_LITERAL"),
            MuteFile.Entry(path: "/Library/\u{1B}Caches/", type: "ES_MUTE_PATH_TYPE_TARGET_PREFIX",
                           events: ["ES_EVENT_TYPE_NOTIFY_CREATE", "ES_EVENT_TYPE_NOTIFY_RENAME"])
        ])
        XCTAssertEqual(text, """
            TYPE            EVENTS          PATH
            literal         every event     /usr/libexec/logd
            target-prefix   create,rename   /Library/\\x1BCaches/

            """)
    }
}
