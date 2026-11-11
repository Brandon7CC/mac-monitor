//
//  CommandLineTool.swift
//  macmonitor
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import SutroESFramework


// MARK: - Command line tool
/// `macmonitor`: read the command line, check root, run the command, exit.
///
/// Everything with logic in it lives in `SutroESFramework`, where the tests reach it. This is process glue. `stream`,
/// `mute` and `indicators` talk to the Security Extension, which decides who may: root, and any user when Settings
/// allows it (`CommandLineAccess`). `status` asks it too, but only reads, so anyone may. `macmonitor` doesn't guess.
/// It asks, and a refusal says how to run the same command line with `sudo`. It refuses to run set-user-ID, so the
/// real and effective users match, and never drops privileges after it connects. `schema` and `validate` need
/// neither root nor the Security Extension.
enum CommandLineTool {
    /// The command line, without the program's name, for a refusal's `sudo` hint.
    private static var arguments: [String] = []
    
    /// Run a command line. Commands that finish right away exit here. `stream` and `validate` return, and exit from
    /// the main queue once they're done.
    ///
    /// - Parameter arguments: The arguments, without the program's name.
    static func run(_ arguments: [String]) {
        Self.arguments = arguments
        let invocation: CommandLineInvocation
        do {
            invocation = try CommandLineParser.parse(arguments)
        } catch {
            fail(.parsing(error))
        }
        if let refusal = invocation.refusal(realUser: getuid(), effectiveUser: geteuid()) { fail(refusal) }
        switch invocation {
        case .help(let command):
            write(CommandLineHelp.text(for: command))
        case .events:
            write(CommandLineHelp.eventList(legend: isatty(STDOUT_FILENO) == 1))
        case .completion(let shell):
            write(CommandLineCompletion.output(for: shell, isTerminal: isatty(STDOUT_FILENO) == 1))
        case .version:
            write("macmonitor \(ToolVersion.current)\n")
            if geteuid() == 0 && getuid() == 0 { write("Security Extension \(sensorVersion())\n") }
        case .stream(let stream):
            StreamRunner.start(stream)
            return
        case .mute(let mute):
            if case .failure(let failure) = runMute(mute) { fail(failure) }
        case .indicators(let indicators):
            if case .failure(let failure) = runIndicators(indicators) { fail(failure) }
        case .status(let status):
            let report = statusReport()
            write(StatusCommand.output(report, json: status.json))
            if !report.isReady { exit(CommandLineExit.unavailable.rawValue) }
        case .schema:
            if case .failure(let failure) = SchemaCommand.run(output: FileOutput(descriptor: STDOUT_FILENO)) {
                fail(failure)
            }
        case .validate(let validate):
            ValidateRunner.start(validate)
            return
        }
        exit(CommandLineExit.success.rawValue)
    }
    
    /// Write text to standard output, exiting 74 if it can't be (but 0 for a closed pipe).
    ///
    /// - Parameter text: The text.
    static func write(_ text: String) {
        do {
            try FileOutput(descriptor: STDOUT_FILENO).write(Data(text.utf8))
        } catch StreamOutputError.failed(let code) {
            fail(.output(code))
        } catch {
            exit(CommandLineExit.success.rawValue)
        }
    }
    
    /// Report a failure on standard error and exit with its status.
    ///
    /// - Parameter failure: The failure.
    /// - Returns: Never.
    static func fail(_ failure: CommandLineFailure) -> Never {
        let failure = failure.suggestingSudo(arguments: arguments, isRoot: geteuid() == 0)
        FileOutput.writeError(failure.description)
        exit(failure.exit.rawValue)
    }
    
    /// Run a mute command over a fresh connection and wait for it. `import` and `reset` ask at the terminal first.
    ///
    /// - Parameter invocation: The command.
    /// - Returns: Success, or why not.
    private static func runMute(_ invocation: MuteInvocation) -> Result<Void, CommandLineFailure> {
        withConnection { client, finish in
            MuteCommand(client: client, output: FileOutput(descriptor: STDOUT_FILENO), diagnose: FileOutput.writeError,
                        confirm: TerminalPrompt.ask)
                .run(invocation, completion: finish)
        }
    }
    
    /// Run an indicator command over a fresh connection and wait for it. `import` asks at the terminal first.
    ///
    /// - Parameter invocation: The command.
    /// - Returns: Success, or why not.
    private static func runIndicators(_ invocation: IndicatorInvocation) -> Result<Void, CommandLineFailure> {
        withConnection { client, finish in
            IndicatorCommand(client: client, output: FileOutput(descriptor: STDOUT_FILENO),
                             diagnose: FileOutput.writeError, confirm: TerminalPrompt.ask)
                .run(invocation, completion: finish)
        }
    }
    
    /// The Security Extension's version, asked over a fresh connection.
    ///
    /// - Returns: Such as "3.0.0 (1)", or why it couldn't be asked.
    private static func sensorVersion() -> String {
        withConnection { client, finish in
            client.send(StreamRequest(.hello), timeout: .seconds(5)) { result in
                switch result {
                case .success(let reply): finish(reply.sensorVersion)
                case .failure(let failure): finish("unavailable: \(failure.message)")
                }
            }
        }
    }
    
    /// Gather what `macmonitor status` shows: this tool's and the app's versions, what macOS says of the System
    /// Extension, and the Security Extension's own answer.
    ///
    /// - Returns: The status.
    private static func statusReport() -> StatusReport {
        let answer: Result<StreamReply, CommandLineFailure> = withConnection { client, finish in
            client.send(StreamRequest(.status), timeout: .seconds(5), completion: finish)
        }
        return StatusReport(tool: ToolVersion.current, app: appInfo().map(StreamService.version(from:)),
                            systemExtension: SystemExtensionList.state(in: systemExtensions()), answer: answer)
    }

    /// Mac Monitor's `Info.plist`, found from where `macmonitor` really is: `Mac Monitor.app/Contents/MacOS`, however
    /// it was run, a link in `/usr/local/bin` included. `Bundle.main` isn't asked: run through a link, it isn't the
    /// app.
    ///
    /// - Returns: The app's keys, or `nil` when `macmonitor` isn't inside Mac Monitor.
    private static func appInfo() -> [String: Any]? {
        guard let executable = Bundle.main.executableURL?.resolvingSymlinksInPath() else { return nil }
        let folder = executable.deletingLastPathComponent(), contents = folder.deletingLastPathComponent()
        guard folder.lastPathComponent == "MacOS", contents.lastPathComponent == "Contents",
              let info = NSDictionary(contentsOf: contents.appendingPathComponent("Info.plist")) as? [String: Any],
              info["CFBundleIdentifier"] as? String == "com.swiftlydetecting.agent" else { return nil }
        return info
    }

    /// - Returns: What `systemextensionsctl list` prints, or nothing when it can't be run.
    private static func systemExtensions() -> String {
        let list = Process(), output = Pipe()
        list.executableURL = URL(fileURLWithPath: "/usr/bin/systemextensionsctl")
        list.arguments = ["list"]
        list.standardOutput = output
        list.standardError = FileHandle.nullDevice
        guard (try? list.run()) != nil else { return "" }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        list.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    /// Make one exchange over a fresh connection that never streams, and wait for it.
    ///
    /// - Parameter body: Starts the exchange on the activated client, and calls its second argument once, from any
    ///   thread, with the answer.
    /// - Returns: The answer.
    private static func withConnection<Answer>(_ body: (StreamClient, @escaping (Answer) -> Void) -> Void) -> Answer {
        let client = StreamClient.live()
        let finished = DispatchSemaphore(value: 0)
        var answer: Answer?
        client.activate(receiving: SilentReceiver()) { _ in }
        body(client) { value in
            answer = value
            finished.signal()
        }
        finished.wait()
        client.invalidate()
        /// The semaphore only signals once `answer` is set.
        return answer!
    }
}


// MARK: - Receiver
/// The receiver for a connection that never streams: `version`, `mute` and `indicators`.
private final class SilentReceiver: NSObject, StreamReaderProtocol {
    /// Reply without reading: nothing streams on this connection.
    ///
    /// - Parameters:
    ///   - events: Ignored.
    ///   - reply: Called right away.
    func receive(events: [Data], reply: @escaping () -> Void) {
        reply()
    }
    
    /// Ignore it: only a stream follows the saved mute set.
    ///
    /// - Parameter change: Ignored.
    func savedMutesChanged(_ change: Data) {}
}
