//
//  StreamRunner.swift
//  macmonitor
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import SutroESFramework


// MARK: - Stream runner
/// `macmonitor stream`, as a process: standard output and error, signals, and the exit status. The stream itself
/// is ``StreamCommand``'s.
///
/// **Stopping:** the first `SIGINT`, `SIGTERM` or `SIGHUP` asks the Security Extension to stop, and batches keep being
/// written until it answers, then `macmonitor` exits by that signal. If the answer doesn't come within 3 seconds
/// (standard output is stalled, say), a ``StopWatchdog`` exits anyway, and so does a second signal. A stream that
/// stops itself at its `--count` or `--for` exits 0.
enum StreamRunner {
    /// Exits when a stop takes longer than its deadline.
    static let watchdog = StopWatchdog()
    
    /// Start streaming to standard output, over the live connection to the Security Extension. Runs on the main
    /// queue until it exits.
    ///
    /// - Parameter invocation: The stream asked for.
    static func start(_ invocation: StreamInvocation) {
        let client = StreamClient.live()
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
            /// Each record lists the indicators the Security Extension matched as it captured the event.
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
            watchdog.arm(for: number)
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
