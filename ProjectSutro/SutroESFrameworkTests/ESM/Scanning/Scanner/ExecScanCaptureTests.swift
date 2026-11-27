//
//  ExecScanCaptureTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/26/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Mac Monitor's serializer with the test's execs
/// Mac Monitor's serializer, with each exec built from the record a test made for it, as the lane builds one: a
/// `ProcessExecEvent` can't be built from a raw message (``RawMessageFixture``). Everything after the build is the
/// serializer's own.
private struct RecordedExecSerializer: EventSerializing {
    /// The execs, by `global_seq_num`.
    let execs: Recorded<(UInt64, Message)>

    /// Serialize a message as Mac Monitor does, an exec from the test's record.
    ///
    /// - Parameters:
    ///   - message: The message.
    ///   - lane: The lane's context.
    /// - Returns: What Mac Monitor's serializer returns.
    func serializeEvent(_ message: UnsafePointer<es_message_t>, in lane: LaneContext) -> SerializedEvent? {
        let serializer = MessageSerializer()
        guard message.pointee.event_type == ES_EVENT_TYPE_NOTIFY_EXEC,
              let exec = execs.all.last(where: { $0.0 == message.pointee.global_seq_num })?.1 else {
            return serializer.serializeEvent(message, in: lane)
        }
        return serializer.serialize(exec, of: message, in: lane)
    }
}


// MARK: - Scanning the scripts execs run
/// Pins scanning the script an exec runs end to end on fake clients, with the stand-in rules (``standInRules()``):
/// Endpoint Security's script and one an interpreter's arguments name are scanned from the bytes the lane read, a
/// script scanned at its close is answered from memory after a chmod, osascript's scripts get XPScripts.yr, the env
/// exec and the osascript exec of one script carry the same result, a script larger than what was read is read again
/// by its path with no symbolic link, an unread script is unreadable, an over_budget exec asks again when the script
/// next runs, an AppleScript applet's main.scpt is scanned whatever its executable is named, a rule on the scan
/// matches the exec held for it, and the scanner is held while execs are subscribed.
final class ExecScanCaptureTests: XCTestCase {
    /// The execs the serializer builds, by `global_seq_num`.
    private let execs = Recorded<(UInt64, Message)>()
    /// What the session emitted.
    private let emitted = EmittedEvents()
    /// Mac Monitor's serializer, building each exec from its record in ``execs``.
    private lazy var serializer = RecordedExecSerializer(execs: execs)

    /// Deliver an exec on the process client: `interpreter` runs with `args` in `directory`, Endpoint Security names
    /// `script` when given, and the lane reads the script as it does for any exec.
    ///
    /// - Parameters:
    ///   - factory: The fake clients.
    ///   - interpreter: The target's executable.
    ///   - args: Its arguments.
    ///   - directory: Its working directory.
    ///   - script: The script Endpoint Security names, and its stat.
    ///   - global: The message's `global_seq_num`.
    ///   - answer: Its launched-by parent, or `nil` for the one opening its record names.
    /// - Throws: The error reading the exec's record.
    private func deliverExec(_ factory: FakeEndpointSecurityClientFactory, _ interpreter: String,
                             args: [String] = [], in directory: String = "/",
                             script: (path: String, info: stat)? = nil, global: UInt64,
                             answer: LaunchedByParent? = nil) throws {
        var message = try importRecord(try esloggerExec(parent: (1, 1), args: [interpreter] + args))
        guard case .exec(var exec) = message.event else { return XCTFail("Not an exec") }
        exec.target.executable = file(interpreter, try fileStat(interpreter))
        exec.cwd = file(directory, try fileStat(directory))
        exec.script = script.map { file($0.path, $0.info) }
        exec.readScript()
        message.event = .exec(exec)
        if let answer { message.setLaunchedByParent(answer) }
        execs.append((global, message))
        factory.client(.process).deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXEC, global: global))
    }

    /// A file as Endpoint Security names one.
    ///
    /// - Parameters:
    ///   - path: Its path.
    ///   - info: Its stat.
    /// - Returns: The file.
    private func file(_ path: String, _ info: stat) -> File {
        var file = File(path: path)
        file.stat = Stat(from: info)
        return file
    }

    /// The execs the process lane emitted, once there are `count`, with each one's scan.
    ///
    /// - Parameter count: How many.
    /// - Returns: Each exec's scan, in order.
    /// - Throws: The error decoding one.
    private func execScans(count: Int) throws -> [YaraScan?] {
        XCTAssertTrue(waitUntil { emitted.all.filter { $0.eventClass == .process }.count >= count })
        return try emitted.all.filter { $0.eventClass == .process }.map { event in
            guard case .exec(let exec) = try JSONDecoder().decode(Message.self, from: event.json).event else {
                return nil
            }
            return exec.yara_scan
        }
    }

    /// A script Endpoint Security names (`./tool.sh`) and one an interpreter's arguments name (`bash tool.sh`) are
    /// both scanned with XProtect.yara, from the bytes the lane read for their text.
    func testEndpointSecuritysScriptAndAnArgumentScriptAreScanned() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let session = try scanningSession(factory, scanner: try makeScanner(), serializer: serializer, emitted: emitted)
        defer { session.stop() }
        let tool = try scannedFile("#!/bin/bash\necho main-marker script-marker\n", name: "tool.sh")
        let other = try scannedFile("echo main-marker\n", name: "other.sh")
        try deliverExec(factory, "/bin/bash", args: [tool.path], script: tool, global: 1)
        try deliverExec(factory, "/bin/bash", args: ["other.sh"], in: other.path.deletingLastPathComponent,
                        global: 2)
        try deliverExec(factory, "/bin/ls", args: [other.path], global: 3)
        XCTAssertEqual(try execScans(count: 3).map { $0?.rules }, [["Main"], ["Main"], nil])
    }

    /// osascript's scripts also get XPScripts.yr, as XProtect evaluates what osascript runs, and another
    /// interpreter's the same text only XProtect.yara. The env exec and the osascript exec of a
    /// `#!/usr/bin/env osascript` script carry the same result.
    func testOsascriptsScriptsGetBothRuleFiles() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let session = try scanningSession(factory, scanner: try makeScanner(), serializer: serializer, emitted: emitted)
        defer { session.stop() }
        let prompt = "display dialog \"main-marker script-marker\"\n"
        let text = try scannedFile(prompt, name: "prompt.txt")
        let copy = try scannedFile(prompt, name: "copy.txt")
        let env = try scannedFile("#!/usr/bin/env osascript\n" + prompt, name: "prompt")
        try deliverExec(factory, "/usr/bin/osascript", args: [text.path], global: 1)
        try deliverExec(factory, "/bin/bash", args: [copy.path], global: 2)
        try deliverExec(factory, "/usr/bin/env", args: [env.path], script: env, global: 3)
        try deliverExec(factory, "/usr/bin/osascript", args: [env.path], global: 4)
        XCTAssertEqual(try execScans(count: 4).map { $0?.rules },
                       [["Main", "Script"], ["Main"], ["Main", "Script"], ["Main", "Script"]])
    }

    /// A script scanned at its close answers its exec after a chmod, which changes only its change time: here the
    /// file is gone before the exec, so only the close's result can answer. A JXA script's close ran XPScripts.yr
    /// too, so it answers the osascript exec that asks for both.
    func testAScriptScannedAtItsCloseAnswersItsExec() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let session = try scanningSession(factory, scanner: try makeScanner(), serializer: serializer, emitted: emitted)
        defer { session.stop() }
        let jxa = try scannedFile("#!/usr/bin/osascript -l JavaScript\nmain-marker script-marker\n", name: "run")
        factory.client(.file).deliver(try fileClose(of: jxa.path, global: 1))
        XCTAssertTrue(waitUntil { emitted.all.contains { $0.eventClass == .file } })
        Thread.sleep(forTimeInterval: 0.01)
        XCTAssertEqual(chmod(jxa.path, 0o755), 0)
        let chmodded = try fileStat(jxa.path)
        XCTAssertNotEqual(FileScanVersion(chmodded), FileScanVersion(jxa.info), "The chmod changed the ctime.")
        XCTAssertEqual(unlink(jxa.path), 0)
        try deliverExec(factory, "/usr/bin/osascript", args: [jxa.path], script: (jxa.path, chmodded), global: 1)
        XCTAssertEqual(try execScans(count: 1).map { $0?.rules }, [["Main", "Script"]])
    }

    /// A modified close forgets what the exec of its file was answered with, whatever the file's type. Here the
    /// script is plain text named .txt, which isn't scanned at its close. Written again with its old size and
    /// modification time (touch -r), its next exec is scanned again.
    func testAnUnscannedCloseForgetsTheOldAnswer() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let session = try scanningSession(factory, scanner: try makeScanner(), serializer: serializer, emitted: emitted)
        defer { session.stop() }
        let script = try scannedFile("echo main-marker\n", name: "x.txt")
        try deliverExec(factory, "/bin/bash", args: [script.path], global: 1)
        XCTAssertEqual(try execScans(count: 1).map { $0?.rules }, [["Main"]])
        _ = try rewrite(script, with: "echo xxxx-marker\n")
        factory.client(.file).deliver(try fileClose(of: script.path, global: 2))
        try deliverExec(factory, "/bin/bash", args: [script.path], global: 3)
        XCTAssertEqual(try execScans(count: 2).map { $0?.rules }, [["Main"], []])
    }

    /// A rule on an exec's scan matches once the scan is done: the exec, held for it, is stamped again as it leaves
    /// the hold, and its hit lists the rule that matched.
    func testARuleOnTheScriptsScanMatches() throws {
        let rule = ownIndicator("Script matched", #"event.exec != nil AND ANY event.exec.yara_scan.rules != """#)
        let gate = DispatchSemaphore(value: 0)
        let factory = FakeEndpointSecurityClientFactory()
        let session = try scanningSession(factory, scanner: try makeScanner(gate: gate), serializer: serializer,
                                          indicators: CompiledIndicators([rule]), emitted: emitted)
        defer { session.stop() }
        let tool = try scannedFile("echo main-marker\n", name: "tool.sh")
        try deliverExec(factory, "/bin/bash", args: [tool.path], global: 1)
        gate.signal()
        XCTAssertEqual(try execScans(count: 1).map { $0?.rules }, [["Main"]])
        let sent = try JSONDecoder().decode(Message.self, from: try XCTUnwrap(emitted.all.first).json)
        XCTAssertEqual(sent.indicators?.hits.map(\.id), [rule.id])
        XCTAssertEqual(sent.indicators?.hits.first?.matched,
                       [IndicatorMatchedField(field: "event.exec.yara_scan.rules", value: .string("Main"))])
    }

    /// A script Endpoint Security names that's gone before the lane reads it, and was never scanned, is unreadable.
    func testAnUnreadScriptIsUnreadable() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let session = try scanningSession(factory, scanner: try makeScanner(), serializer: serializer, emitted: emitted)
        defer { session.stop() }
        let tool = try scannedFile("#!/bin/sh\nrm \"$0\"\n", name: "gone.sh")
        XCTAssertEqual(unlink(tool.path), 0)
        try deliverExec(factory, "/bin/sh", args: [tool.path], script: tool, global: 1)
        XCTAssertEqual(try execScans(count: 1).map { $0?.status }, [YaraScan.unreadable])
    }

    /// A script larger than the lane read, here one whose text a NUL ends within the first bytes, is read again by
    /// the path with no symbolic link the lane's open file has, though the arguments name it through a link.
    func testAScriptLargerThanWhatWasReadIsReadByItsPath() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let session = try scanningSession(factory, scanner: try makeScanner(), serializer: serializer, emitted: emitted)
        defer { session.stop() }
        let header = "#!/bin/sh\nexit 0\n"
        let payload = Array(header.utf8) + [0] + Array(repeating: 0x61, count: 1024) + Array("main-marker".utf8)
        let directory = try temporaryFile(bytes: payload, named: "installer.run").deletingLastPathComponent
        let link = try makeTemporaryDirectory().appendingPathComponent("linked").path
        XCTAssertEqual(symlink(directory, link), 0)
        try deliverExec(factory, "/bin/bash", args: [link.appendingPathComponent("installer.run")], global: 1)
        XCTAssertEqual(try execScans(count: 1).map { $0?.rules }, [["Main"]])
    }

    /// An exec whose scan the budget refused is over_budget, and isn't remembered: the script's next exec, once the
    /// budget has refilled, is scanned.
    func testOverBudgetAsksAgainAtTheNextRun() throws {
        var now: TimeInterval = 0
        let clock = { now }
        let gate = DispatchSemaphore(value: 0)
        let budget = FileScanBudget(refillPerSecond: 0.05, capacity: 0.00015, window: 1, clock: clock)
        let factory = FakeEndpointSecurityClientFactory()
        let session = try scanningSession(factory, scanner: try makeScanner(budget: budget, gate: gate),
                                          serializer: serializer, emitted: emitted)
        defer { session.stop() }
        let first = try scannedFile("echo main-marker\n", name: "first.sh")
        let second = try scannedFile("echo main-marker again\n", name: "second.sh")
        try deliverExec(factory, "/bin/bash", args: [first.path], global: 1)
        try deliverExec(factory, "/bin/bash", args: [second.path], global: 2)
        gate.signal()
        XCTAssertEqual(try execScans(count: 2).map { $0?.status }, [YaraScan.scanned, YaraScan.overBudget])
        now += 10
        try deliverExec(factory, "/bin/bash", args: [second.path], global: 3)
        XCTAssertEqual(try execScans(count: 3).map { $0?.status },
                       [YaraScan.scanned, YaraScan.overBudget, YaraScan.scanned])
    }

    /// An AppleScript applet's exec runs its Mach-O stub, which loads Contents/Resources/Scripts/main.scpt: the exec
    /// carries main.scpt's scan with both rule files, once its Launch Services lookup is done too. A stub without
    /// main.scpt and another app's exec have no scan.
    func testAnAppletsScriptIsScanned() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let session = try scanningSession(factory, scanner: try makeScanner(), serializer: serializer,
                                          launchServices: FakeLaunchServicesReader(), emitted: emitted)
        defer { session.stop() }
        let stub = try applet(named: "Invoice", script: Data("FasdUAS 1.101.10".utf8) + Data([0x0E, 0, 0])
                                + Data("main-marker script-marker".utf8))
        try deliverExec(factory, stub, global: 1, answer: .appJob())
        try deliverExec(factory, try applet(named: "Empty", script: nil), global: 2, answer: .appJob())
        try deliverExec(factory, "/bin/ls", global: 3, answer: .appJob())
        XCTAssertEqual(try execScans(count: 3).map { $0?.rules }, [["Main", "Script"], nil, nil])
    }

    /// The stub loads main.scpt whatever its executable is named, so an applet whose executable was renamed, here to
    /// Invoice, is scanned too. A file in a bundle's Contents/MacOS that isn't its executable's folder is not.
    func testARenamedAppletsScriptIsScanned() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let session = try scanningSession(factory, scanner: try makeScanner(), serializer: serializer,
                                          launchServices: FakeLaunchServicesReader(), emitted: emitted)
        defer { session.stop() }
        let script = Data("FasdUAS 1.101.10".utf8) + Data([0x0E, 0, 0]) + Data("main-marker script-marker".utf8)
        let stub = try applet(named: "Statement", executable: "Invoice", script: script)
        try deliverExec(factory, stub, global: 1, answer: .appJob())
        let nested = stub.deletingLastPathComponent.appendingPathComponent("Helpers/tool")
        try FileManager.default.createDirectory(atPath: nested.deletingLastPathComponent,
                                                withIntermediateDirectories: true)
        try Data(FileTypeSamples.machO(MH_EXECUTE)).write(to: URL(fileURLWithPath: nested))
        try deliverExec(factory, nested, global: 2, answer: .appJob())
        XCTAssertEqual(try execScans(count: 2).map { $0?.rules }, [["Main", "Script"], nil])
    }

    /// An applet bundle as Script Editor saves one: a Mach-O stub, and its compiled script.
    ///
    /// - Parameters:
    ///   - name: The bundle's name, without `.app`.
    ///   - executable: The stub's name: `applet` unless it was renamed.
    ///   - script: Contents/Resources/Scripts/main.scpt's bytes, or `nil` for none.
    /// - Returns: The stub's path, in Contents/MacOS.
    /// - Throws: The error writing it.
    private func applet(named name: String, executable: String = "applet", script: Data?) throws -> String {
        let bundle = try resolvedTemporaryDirectory().appendingPathComponent(name + ".app")
        let stub = bundle.appendingPathComponent("Contents/MacOS").appendingPathComponent(executable)
        try FileManager.default.createDirectory(atPath: stub.deletingLastPathComponent,
                                                withIntermediateDirectories: true)
        try Data(FileTypeSamples.machO(MH_EXECUTE)).write(to: URL(fileURLWithPath: stub))
        if let script {
            let scripts = bundle.appendingPathComponent("Contents/Resources/Scripts")
            try FileManager.default.createDirectory(atPath: scripts, withIntermediateDirectories: true)
            try script.write(to: URL(fileURLWithPath: scripts.appendingPathComponent("main.scpt")))
        }
        return stub
    }

    /// The scanner is held while the session subscribes to execs or closes, and released without either.
    func testTheScannerFollowsTheExecSubscription() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let scanner = try makeScanner()
        let session = try scanningSession(factory, scanner: scanner, serializer: serializer,
                                          events: [ES_EVENT_TYPE_NOTIFY_EXEC], emitted: emitted)
        defer { session.stop() }
        XCTAssertTrue(scanner.isInUse)
        XCTAssertTrue(session.setSubscription(ES_EVENT_TYPE_NOTIFY_CLOSE, enabled: true))
        XCTAssertTrue(session.setSubscription(ES_EVENT_TYPE_NOTIFY_EXEC, enabled: false))
        XCTAssertTrue(scanner.isInUse, "Closes are still subscribed")
        XCTAssertTrue(session.setSubscription(ES_EVENT_TYPE_NOTIFY_CLOSE, enabled: false))
        XCTAssertFalse(scanner.isInUse)
    }
}
