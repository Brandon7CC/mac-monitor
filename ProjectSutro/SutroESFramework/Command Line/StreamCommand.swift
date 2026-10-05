//
//  StreamCommand.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Output
/// Where `macmonitor` writes events: standard output in the tool, a buffer in the tests.
public protocol StreamOutput: AnyObject {
    /// Write all of `data`, however long that takes.
    ///
    /// - Parameter data: The bytes.
    /// - Throws: ``StreamOutputError``.
    func write(_ data: Data) throws
}


/// Why output couldn't be written.
public enum StreamOutputError: Error, Equatable {
    /// The reader went away (`EPIPE`), as `| head` does once it has its lines: not a failure.
    case closed
    /// Another write error, by `errno`.
    case failed(Int32)
}


// MARK: - Stream command
/// `macmonitor stream` (command line context): start the stream, write each batch, report drops, stop.
///
/// Each batch is written on one serial queue, then replied to: the reply is the stream's back-pressure, so a slow
/// reader slows the Security Extension's batches for this stream only, and past its buffer the stream pauses. A stop
/// is answered only once every batch before it has been replied to, so by the time the answer is handled here every
/// event captured before the stop has been written.
///
/// Diagnostics go to standard error: a drop notice at most once a second, a version mismatch, each change to the
/// saved mute set the stream follows, and (when standard error is a terminal) a banner and a summary.
public final class StreamCommand: NSObject {
    /// How a stream ended.
    public enum Outcome: Equatable {
        /// A stop was answered, with what the stream delivered and lost (`nil` if the answer had none).
        case stopped(StreamSummary?)
        /// The reader closed standard output (`| head`): a success.
        case outputClosed
        /// The stream couldn't start or went away.
        case failed(CommandLineFailure)
    }
    
    /// The shortest time between two drop notices, in nanoseconds.
    static let noticeInterval: UInt64 = 1_000_000_000
    private let client: StreamClient
    private let pipeline: StreamPipeline
    private let output: StreamOutput
    /// Writes one line to standard error.
    private let diagnose: (String) -> Void
    /// Banner and summary: only when standard error is a terminal.
    private let isChatty: Bool
    /// `macmonitor`'s own version, such as "2.2.0 (1)".
    private let toolVersion: String
    /// Writes batches and handles answers, in order.
    private let queue = DispatchQueue(label: "com.swiftlydetecting.agent.cli.stream")
    /// Called once, on ``queue``, with how the stream ended.
    private var completion: ((Outcome) -> Void)?
    /// When the last drop notice was written (uptime nanoseconds).
    private var lastNotice: UInt64 = 0
    
    /// - Parameters:
    ///   - client: The connection to the Security Extension, not yet activated.
    ///   - pipeline: Turns batches into output.
    ///   - output: Where events are written.
    ///   - toolVersion: `macmonitor`'s own version.
    ///   - isChatty: Write the banner and the summary (standard error is a terminal).
    ///   - diagnose: Writes one line to standard error.
    public init(client: StreamClient, pipeline: StreamPipeline, output: StreamOutput, toolVersion: String,
                isChatty: Bool, diagnose: @escaping (String) -> Void) {
        self.client = client
        self.pipeline = pipeline
        self.output = output
        self.toolVersion = toolVersion
        self.isChatty = isChatty
        self.diagnose = diagnose
    }
    
    /// Start streaming.
    ///
    /// - Parameters:
    ///   - invocation: The stream asked for.
    ///   - completion: Called once, on the command's queue, with how the stream ended.
    public func run(_ invocation: StreamInvocation, completion: @escaping (Outcome) -> Void) {
        queue.sync { self.completion = completion }
        client.activate(receiving: self) { [weak self] failure in
            self?.queue.async { self?.end(.failed(failure)) }
        }
        client.send(StreamRequest(.stream, options: invocation.options), timeout: .seconds(10)) { [self] result in
            queue.async { [self] in
                switch result {
                case .failure(let failure):
                    end(.failed(failure))
                case .success(let reply):
                    if let failure = CommandLineFailure.reply(reply) { return end(.failed(failure)) }
                    started(reply)
                }
            }
        }
    }
    
    /// Stop: no new events, write every event already captured, then end with the summary.
    ///
    /// - Parameter timeout: How long to wait for the Security Extension's answer.
    public func stop(timeout: DispatchTimeInterval = .seconds(2)) {
        client.send(StreamRequest(.stop), timeout: timeout) { [self] result in
            queue.async { [self] in
                switch result {
                case .success(let reply): end(.stopped(reply.summary))
                case .failure(let failure): end(.failed(failure))
                }
            }
        }
    }
}


// MARK: - Receiving
extension StreamCommand: StreamReaderProtocol {
    /// Write a batch, then reply. Once the stream has ended, reply right away and write nothing.
    ///
    /// - Parameters:
    ///   - events: Wire events, oldest first.
    ///   - reply: Lets the Security Extension send the next batch.
    public func receive(events: [Data], reply: @escaping () -> Void) {
        queue.async { [self] in
            defer { reply() }
            guard completion != nil else { return }
            do {
                try output.write(pipeline.process(events))
            } catch StreamOutputError.closed {
                return end(.outputClosed)
            } catch StreamOutputError.failed(let code) {
                return end(.failed(.output(code)))
            } catch {
                return end(.failed(.output(EIO)))
            }
            noticeDrops()
        }
    }
    
    /// Say that the saved mute set changed, terminal or not: the stream stops showing what it now mutes, and muted
    /// events never show as lost.
    ///
    /// - Parameter change: A JSON encoded ``MuteSetChange``.
    public func savedMutesChanged(_ change: Data) {
        queue.async { [self] in
            guard completion != nil else { return }
            diagnose("macmonitor: \(Self.describe(MuteSetChange.decode(change)))")
        }
    }
}


// MARK: - Diagnostics
extension StreamCommand {
    /// The stream started: say so, and warn if the Security Extension is another version. Call on ``queue``.
    ///
    /// - Parameter reply: The stream request's answer.
    private func started(_ reply: StreamReply) {
        if reply.sensorVersion != toolVersion {
            diagnose("""
                macmonitor: macmonitor is \(toolVersion) but the Security Extension is \(reply.sensorVersion). Open \
                Mac Monitor to finish updating.
                """)
        }
        guard isChatty, let stream = reply.stream else { return }
        /// Say how to see what the saved set hides: a stream applies it unless asked not to.
        let mutes = stream.savedMutes.map { "with \($0) saved mutes (--no-mutes shows everything)" }
            ?? "without the saved mutes"
        let events = String.counted(stream.events.count, "event")
        diagnose("macmonitor: streaming \(events) \(mutes). Press Ctrl-C to stop.")
    }
    
    /// Write a notice for events lost since the last one, at most once every ``noticeInterval``. Call on ``queue``.
    ///
    /// - Parameter now: The uptime in nanoseconds.
    private func noticeDrops(now: UInt64 = DispatchTime.now().uptimeNanoseconds) {
        guard now &- lastNotice >= Self.noticeInterval else { return }
        let reports = pipeline.meter.takeReport()
        guard !reports.isEmpty else { return }
        lastNotice = now
        diagnose("macmonitor: \(Self.lost(reports))")
    }
    
    /// Events lost, in a few words: "lost 120 events (open 100, close 20)".
    ///
    /// - Parameter reports: Drops by client.
    /// - Returns: The words.
    static func lost(_ reports: [CaptureDropReport]) -> String {
        let total = reports.reduce(0) { $0 + $1.dropped }
        let byType = reports.flatMap(\.droppedByType).reduce(into: [String: UInt64]()) { counts, entry in
            counts[entry.key, default: 0] += entry.value
        }
        let types = byType.sorted { ($1.value, $0.key) < ($0.value, $1.key) }
            .map { "\(CommandLineEvents.shortName($0.key)) \($0.value)" }
        let detail = types.isEmpty ? "" : " (\(types.joined(separator: ", ")))"
        return "lost \(String.counted(total, "event"))\(detail)"
    }
    
    /// A change to the saved mute set, in a sentence.
    ///
    /// - Parameter change: The change, or `nil` if it didn't read.
    /// - Returns: Such as "Mac Monitor (pid 501) changed the saved mute set: 1 added, 0 removed, 0 changed, 79 mutes
    ///   now. This stream applies it; --no-mutes shows everything."
    static func describe(_ change: MuteSetChange?) -> String {
        let consequence = "This stream applies it; --no-mutes shows everything."
        guard let change else { return "The saved mute set changed. \(consequence)" }
        return """
            \(TerminalSafeText.text(change.caller)) changed the saved mute set: \(change.added) added, \
            \(change.removed) removed, \(change.changed) changed, \(String.counted(change.mutes, "mute")) now. \
            \(consequence)
            """
    }
    
    /// End the stream once: write the summary when there is one and it's wanted, complete, and close the connection.
    /// Call on ``queue``.
    ///
    /// - Parameter outcome: How the stream ended.
    private func end(_ outcome: Outcome) {
        guard let completion else { return }
        self.completion = nil
        if case .stopped(let summary?) = outcome, isChatty {
            let lost = pipeline.meter.dropped, byEndpointSecurity = UInt64(summary.droppedByEndpointSecurity)
            diagnose("""
                macmonitor: wrote \(pipeline.written) events, lost \(lost) (\(min(lost, byEndpointSecurity)) by \
                Endpoint Security, \(lost - min(lost, byEndpointSecurity)) while macmonitor was behind).
                """)
        }
        if pipeline.unreadable > 0 {
            diagnose("macmonitor: \(pipeline.unreadable) events couldn't be read.")
        }
        completion(outcome)
        /// The Security Extension closes the stream, if it hasn't already.
        client.invalidate()
    }
}
