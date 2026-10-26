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
/// (standard output is stalled, say), a watchdog exits anyway, and so does a second signal. A stream that stops itself
/// at its `--count` or `--for` exits 0.
enum StreamRunner {
    /// How long a stop may take before the watchdog exits.
    static let stopDeadline: DispatchTimeInterval = .seconds(3)
    
    /// Start streaming to standard output. Runs on the main queue until it exits.
    ///
    /// - Parameters:
    ///   - invocation: The stream asked for.
    ///   - client: The connection to the Security Extension: the live one, unless a probe brings its own.
    static func start(_ invocation: StreamInvocation, client: StreamClient = .live()) {
        let isTerminal = isatty(STDOUT_FILENO) == 1
        let format = invocation.resolvedFormat(isTerminal: isTerminal)
        let formatter: StreamPipeline.Formatter
        if format == .text && !invocation.filter.readsRecords {
            formatter = .text(TextEventFormatter())
        } else {
            /// JSONL, or text with a filter that reads each event's record.
            guard let model = ExportEncoder.model else {
                CommandLineTool.fail(CommandLineFailure(.software, "Mac Monitor's event model is missing."))
            }
            let encoders = StreamPipeline.Formatter.encoders(model: model, pretty: format == .pretty)
            formatter = format == .text ? .text(TextEventFormatter(), records: encoders) : .jsonl(encoders)
        }
        let pipeline = StreamPipeline(formatter: formatter, scope: .current(includeSelf: invocation.includeSelf),
                                      forTerminal: isTerminal, filter: invocation.filter, limit: invocation.limit)
        let command = StreamCommand(client: client, pipeline: pipeline, output: FileOutput(descriptor: STDOUT_FILENO),
                                    toolVersion: ToolVersion.current, isChatty: isatty(STDERR_FILENO) == 1,
                                    diagnose: FileOutput.writeError)
        let trap = SignalTrap.start { number in
            command.stop()
            DispatchQueue.global().asyncAfter(deadline: .now() + Self.stopDeadline) { _exit(128 + number) }
        }
        /// 0 for a stream that stopped itself or lost its reader, else the failure's status.
        command.run(invocation) { outcome in
            DispatchQueue.main.async {
                if case .failed(let failure) = outcome { trap.finish(failure) }
                trap.finish()
            }
        }
    }
}
