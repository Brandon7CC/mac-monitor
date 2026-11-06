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
/// Everything with logic in it lives in `SutroESFramework`, where the tests reach it; this is process glue. Only
/// `stream` and `mute` talk to the Security Extension, which decides who may: root, and any user when Settings allows
/// it (`CommandLineAccess`). `macmonitor` doesn't guess. It asks, and a refusal says how to run the same command
/// line with `sudo`. It refuses to run set-user-ID, so the real and effective users match, and never drops privileges
/// after it connects. `schema` and `validate` need neither root nor the Security Extension.
enum CommandLineTool {
    /// The command line, without the program's name, for a refusal's `sudo` hint.
    private static var arguments: [String] = []
    
    /// Run a command line. Commands that finish right away exit here; `stream` and `validate` return, and exit from
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
        if invocation.requiresRoot && geteuid() != getuid() {
            fail(.setUserID(invocation.command))
        }
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
/// The receiver for a connection that never streams: `version` and `mute`.
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
