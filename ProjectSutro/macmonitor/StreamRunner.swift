//
//  StreamRunner.swift
//  macmonitor
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import SutroESFramework


// MARK: - Stream runner
/// `sudo macmonitor stream`, as a process: standard output and error, signals, and the exit status. The stream itself
/// is ``StreamCommand``'s.
///
/// **Stopping:** the first `SIGINT`, `SIGTERM` or `SIGHUP` asks the Security Extension to stop, and batches keep being
/// written until it answers; then `macmonitor` exits by that signal. If the answer doesn't come within the stop timeout
/// (standard output is stalled, say), a watchdog exits anyway, and so does a second signal.
final class StreamRunner {
    /// How long a stop may take before the watchdog exits.
    static let stopDeadline: DispatchTimeInterval = .seconds(3)
    /// The one stream this process runs.
    private static var current: StreamRunner?
    private let command: StreamCommand
    private var trap: SignalTrap?
    /// The signal that started the stop, if one did.
    private var stoppingSignal: Int32?
    
    /// - Parameter command: The stream.
    private init(command: StreamCommand) {
        self.command = command
    }
    
    /// Start streaming to standard output. Runs on the main queue until it exits.
    ///
    /// - Parameters:
    ///   - invocation: The stream asked for.
    ///   - client: The connection to the Security Extension: the live one, unless a probe brings its own.
    static func start(_ invocation: StreamInvocation, client: StreamClient = .live()) {
        let isTerminal = isatty(STDOUT_FILENO) == 1
        let formatter: StreamPipeline.Formatter
        switch invocation.resolvedFormat(isTerminal: isTerminal) {
        case .text:
            formatter = .text(TextEventFormatter())
        case .jsonl:
            guard let model = ExportEncoder.model else {
                CommandLineTool.fail(CommandLineFailure(.software, "Mac Monitor's event model is missing."))
            }
            formatter = .jsonl(model: model)
        }
        let pipeline = StreamPipeline(formatter: formatter, scope: .current(includeSelf: invocation.includeSelf),
                                      forTerminal: isTerminal)
        let command = StreamCommand(client: client, pipeline: pipeline, output: FileOutput(descriptor: STDOUT_FILENO),
                                    toolVersion: ToolVersion.current, isChatty: isatty(STDERR_FILENO) == 1,
                                    diagnose: FileOutput.writeError)
        let runner = StreamRunner(command: command)
        current = runner
        runner.trap = SignalTrap { [weak runner] number in runner?.received(number) }
        command.run(invocation) { outcome in
            DispatchQueue.main.async { runner.finish(outcome) }
        }
    }
    
    /// Stop on the first signal; exit on the second.
    ///
    /// - Parameter number: The signal.
    private func received(_ number: Int32) {
        guard stoppingSignal == nil else { _exit(128 + number) }
        stoppingSignal = number
        command.stop()
        DispatchQueue.global().asyncAfter(deadline: .now() + Self.stopDeadline) { _exit(128 + number) }
    }
    
    /// Exit the way the stream ended: by the signal that stopped it, else 0 for a closed pipe, or the failure's status.
    /// A reader that went away after the signal (Ctrl-C stops `| jq` too) still exits by the signal.
    ///
    /// - Parameter outcome: How the stream ended.
    private func finish(_ outcome: StreamCommand.Outcome) {
        if let stoppingSignal { SignalTrap.exit(by: stoppingSignal) }
        if case .failed(let failure) = outcome { CommandLineTool.fail(failure) }
        exit(CommandLineExit.success.rawValue)
    }
}
