//
//  StreamSession.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import OSLog


// MARK: - Stream session
/// One `macmonitor` connection (Security Extension context): at most one stream, on its own capture session.
///
/// **Stream:** a stream request reserves a slot, follows the saved mute set (unless `--no-mutes`), and starts a
/// capture session whose events go through an ``EventBatcher`` with the
/// ``EventBatcher/Limits-swift.struct/commandLine`` limits. When `macmonitor` falls behind, the batcher pauses capture
/// rather than buffering without bound; `macmonitor` sees what it missed as `global_seq_num` gaps, and the summary
/// counts it. Each change to the saved set is applied, then told to `macmonitor`
/// (``StreamReaderProtocol/savedMutesChanged(_:)``), since muted events never show as gaps.
///
/// **Stop:** a stop request drains the capture session and the batcher, so everything captured up to that moment is
/// delivered, then answers with a ``StreamSummary`` and closes. Closing (also when the connection goes away) deletes
/// the clients, frees the slot, and lets a Mac Monitor that Endpoint Security refused for want of clients try again
/// (``StreamService/released``).
///
/// **Threading:** every piece of state below lives on ``queue``. Requests are checked on the thread delivering them,
/// then hop onto it.
final class StreamSession: NSObject {
    /// The session's number, which keys its slot.
    let number: UInt64
    /// Serializes the session's state, capture calls, and batching.
    private let queue: DispatchQueue
    /// The connection, held strongly only by the batcher while streaming.
    private weak var connection: NSXPCConnection?
    private let service: StreamService
    /// Names the session in the log, such as "macmonitor (pid 4211)". The process ID is only a hint.
    private let label: String
    private var capture: CaptureSession?
    private var batcher: EventBatcher?
    /// Applies saved mute set changes to `capture` while held.
    private var muteSubscription: MuteSubscription?
    /// Has the connection asked to stream? One stream a connection.
    private var hasStreamed: Bool = false
    private var isClosed: Bool = false
    /// Capture's skipped messages when the batcher last paused it, while it's paused.
    private var skippedAtPause: UInt64?
    /// Messages capture skipped during earlier pauses.
    private var skippedWhilePaused: UInt64 = 0
    
    /// - Parameters:
    ///   - connection: The `macmonitor` connection.
    ///   - service: The service that accepted it.
    ///   - number: The session's number.
    init(connection: NSXPCConnection, service: StreamService, number: UInt64) {
        self.number = number
        self.connection = connection
        self.service = service
        label = "macmonitor (pid \(connection.processIdentifier))"
        queue = DispatchQueue(label: "com.swiftlydetecting.agent.securityextension.stream.\(number)")
    }
    
    /// Close the stream, from any thread: delete the clients, drop what's buffered, and free the slot. Calling it again
    /// does nothing.
    func close() {
        queue.async { [self] in finish() }
    }
}


// MARK: - StreamProtocol
extension StreamSession: StreamProtocol {
    func perform(_ request: Data, reply: @escaping (Data) -> Void) {
        /// The router only hands root's connections here; check again on the thread delivering the message.
        guard service.admits(NSXPCConnection.current()) else {
            StreamService.logger.error("\(self.label, privacy: .public): refused a stream request from non-root.")
            return reply(answer(.refused, problem: "Only root can use macmonitor.").encoded())
        }
        queue.async { [self] in
            respond(to: request) { reply($0.encoded()) }
        }
    }
    
    func mutes(_ request: Data, reply: @escaping (Data) -> Void) {
        guard service.admits(NSXPCConnection.current()) else {
            StreamService.logger.error("\(self.label, privacy: .public): refused a mute request from non-root.")
            return reply(MuteReply(status: .refused, mutes: [], problems: ["Only root can use macmonitor."]).encoded())
        }
        service.savedMutes.handle(request, access: .write, caller: label, reply: reply)
    }
}


// MARK: - Requests
extension StreamSession {
    /// Answer a request. Call on ``queue``.
    ///
    /// - Parameters:
    ///   - data: A JSON encoded ``StreamRequest``.
    ///   - reply: Receives the answer, on ``queue``: right away, or once a stop has drained.
    private func respond(to data: Data, reply: @escaping (StreamReply) -> Void) {
        do {
            let request = try StreamRequest.decode(data)
            switch request.kind {
            case .hello:
                reply(answer(.ok))
            case .stream:
                reply(start(try StreamPlan(request.options ?? StreamOptions())))
            case .stop:
                stop(reply: reply)
            }
        } catch {
            let problem = (error as? XPCRequestError) ?? .invalid("\(error)")
            reply(answer(problem.status(), problem: problem.description))
        }
    }
    
    /// Start the connection's stream: reserve a slot, follow the saved mute set if asked, and start capture.
    ///
    /// The mutes and subscriptions are in place before capture starts recording, so no message arrives unmuted.
    ///
    /// - Parameter plan: The validated request.
    /// - Returns: The answer: what the stream subscribed to, or why it couldn't start.
    private func start(_ plan: StreamPlan) -> StreamReply {
        guard !hasStreamed, !isClosed, let connection else {
            return answer(.alreadyStreaming, problem: "This connection has already streamed. Connect again to stream.")
        }
        guard service.slots.reserve(number) else {
            return answer(.sessionLimit, problem: """
                \(service.slots.capacity) macmonitor streams are already running. Stop one, then try again.
                """)
        }
        hasStreamed = true
        var configuration = CaptureConfiguration(events: plan.events, label: label)
        if plan.appliesSavedMutes {
            /// Follow the saved set from the moment it's read, so no change is missed. Changes hop onto `queue`.
            let (mutes, subscription) = service.savedMutes.follow { [weak self] list, change in
                self?.queue.async { self?.apply(list, change) }
            }
            configuration.mutes = mutes
            muteSubscription = subscription
        }
        let batcher = EventBatcher(queue: queue, limits: .commandLine,
                                   overflow: .pause { [weak self] paused in self?.setPaused(paused) },
                                   delivery: XPCBatchDelivery(connection: connection, label: label),
                                   willSend: { [weak self] in self?.capture?.reportDrops() }, label: label)
        do {
            let capture = try service.makeCapture(configuration) { [weak self] event in
                self?.queue.async { self?.batcher?.enqueue(event.json) }
            }
            self.batcher = batcher
            self.capture = capture
            capture.isRecording = true
            let savedMutes = plan.appliesSavedMutes ? configuration.mutes.count : nil
            StreamService.logger.log("""
                \(self.label, privacy: .public) started a stream of \(capture.subscribedEvents.count) events \
                \(savedMutes.map { "with \($0) saved mutes" } ?? "without the saved mutes", privacy: .public).
                """)
            let events = capture.subscribedEvents.map { eventTypeToString(from: $0) }
            return answer(.ok, stream: StreamStarted(events: events, savedMutes: savedMutes))
        } catch {
            muteSubscription?.cancel()
            muteSubscription = nil
            service.slots.release(number)
            return startFailure(error)
        }
    }
    
    /// Stop new events, deliver every event already captured, then answer with the summary and close.
    ///
    /// - Parameter reply: Receives the answer once `macmonitor` has replied to every batch.
    private func stop(reply: @escaping (StreamReply) -> Void) {
        guard let capture, let batcher, !isClosed else { return reply(answer(.ok)) }
        capture.drain(on: queue) { [self] in
            batcher.drain { [self] in
                reply(answer(.ok, summary: summary()))
                finish()
            }
        }
    }
    
    /// Close for good. Call on ``queue``.
    private func finish() {
        guard !isClosed else { return }
        isClosed = true
        let heldClients = capture != nil
        if heldClients {
            let summary = summary()
            StreamService.logger.log("""
                \(self.label, privacy: .public) closed its stream: delivered \(summary.delivered) of \
                \(summary.captured) events, \(summary.pauses) pauses, \
                \(summary.droppedWhileBehind + summary.skippedWhilePaused) lost while behind \
                (\(summary.droppedWhileBehind) dropped with the buffer full, \(summary.skippedWhilePaused) skipped \
                while paused), \(summary.droppedByEndpointSecurity) dropped by Endpoint Security.
                """)
        }
        muteSubscription?.cancel()
        muteSubscription = nil
        capture?.stop()
        batcher?.close()
        /// Releasing the batcher releases its delivery, the only strong reference to the connection.
        capture = nil
        batcher = nil
        service.slots.release(number)
        if heldClients { service.released() }
    }
    
    /// Apply a change to the saved mute set, then tell `macmonitor`. Call on ``queue``.
    ///
    /// - Parameters:
    ///   - list: The saved set now.
    ///   - change: Who changed it how.
    private func apply(_ list: MuteList, _ change: MuteSetChange) {
        guard let capture, !isClosed else { return }
        capture.applyMutes(list)
        let proxy = connection?.remoteObjectProxyWithErrorHandler { _ in }
        (proxy as? StreamReaderProtocol)?.savedMutesChanged(change.encoded())
    }
    
    /// Pause or resume capture for the batcher, counting what capture skips while paused. Call on ``queue``.
    ///
    /// The skipped count is read before recording stops and after it starts again, so every message skipped in
    /// between, and only those, is counted.
    ///
    /// - Parameter paused: `true` to pause.
    private func setPaused(_ paused: Bool) {
        guard let capture else { return }
        if paused {
            skippedAtPause = capture.skippedMessages
            capture.isRecording = false
        } else {
            capture.isRecording = true
            skippedWhilePaused += skippedAtPause.map { capture.skippedMessages - $0 } ?? 0
            skippedAtPause = nil
        }
    }
}


// MARK: - Answers
extension StreamSession {
    /// An answer with the Security Extension's version.
    ///
    /// - Parameters:
    ///   - status: How the request went.
    ///   - problem: What went wrong.
    ///   - stream: The stream that started.
    ///   - summary: What the stream delivered and lost.
    /// - Returns: The answer.
    private func answer(_ status: StreamReply.Status, problem: String? = nil, stream: StreamStarted? = nil,
                        summary: StreamSummary? = nil) -> StreamReply {
        StreamReply(status, problem: problem, sensorVersion: service.sensorVersion, stream: stream, summary: summary)
    }
    
    /// What the stream has delivered and lost so far. Call on ``queue``.
    ///
    /// - Returns: The summary.
    private func summary() -> StreamSummary {
        let counters = batcher?.counters ?? EventBatcherCounters()
        let droppedByEndpointSecurity = (capture?.statistics() ?? []).reduce(0) { $0 + Int($1.dropped) }
        var skipped = skippedWhilePaused
        /// A pause still going counts up to now.
        if let skippedAtPause, let capture { skipped += capture.skippedMessages - skippedAtPause }
        return StreamSummary(captured: counters.enqueued, delivered: counters.delivered,
                             droppedByEndpointSecurity: droppedByEndpointSecurity,
                             droppedWhileBehind: counters.dropped,
                             skippedWhilePaused: Int(skipped), pauses: counters.pauses)
    }
    
    /// The answer for a capture session that couldn't start.
    ///
    /// - Parameter error: What the capture session threw.
    /// - Returns: The answer.
    private func startFailure(_ error: Error) -> StreamReply {
        StreamService.logger.error("""
            \(self.label, privacy: .public): Endpoint Security refused the stream: \
            \(String(describing: error), privacy: .public)
            """)
        switch (error as? CaptureStartError)?.clientResult {
        case .tooManyClients?:
            return answer(.clientLimit, problem: """
                Endpoint Security has too many clients. Stop another stream or Endpoint Security tool, then try again.
                """)
        case .notPermitted?:
            return answer(.notPermitted, problem: """
                The Security Extension doesn't have Full Disk Access. Allow it in System Settings > Privacy & \
                Security > Full Disk Access.
                """)
        default:
            return answer(.failed, problem: "Endpoint Security refused the stream (\(error)).")
        }
    }
}
