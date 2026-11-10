//
//  SensorService+Capture.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Event streaming
extension SensorService {
    /// Start capture if there's no session yet, else refresh its Sensor ID (which follows the console user). Call on
    /// `queue`.
    ///
    /// - Returns: `.success`, or why Endpoint Security refused, such as `.tooManyClients`.
    func startCapture() -> NewClientResult {
        if let capture {
            capture.refreshSensorID()
            return .success
        }
        /// Follow the saved sets from the moment they're read, so no change is missed. Changes hop onto `queue`.
        let (mutes, subscription) = savedMutes.follow { [weak self] list, _ in
            self?.queue.async { self?.capture?.applyMutes(list) }
        }
        let (indicators, followingIndicators) = savedIndicators.follow { [weak self] compiled in
            self?.queue.async { self?.capture?.applyIndicators(compiled) }
        }
        do {
            var configuration = CaptureConfiguration(events: subscriptions, label: "Mac Monitor")
            configuration.mutes = mutes
            configuration.fieldFilters = fieldFilters
            configuration.indicators = indicators
            let session = try makeCapture(configuration) { [weak self] event in
                self?.queue.async { self?.sink?.batcher.enqueue(event.json) }
            }
            if appleDefaultMutes.isEmpty { appleDefaultMutes = session.appleMuteSet }
            capture = session
            muteSubscription = subscription
            indicatorSubscription = followingIndicators
            return .success
        } catch {
            return (error as? CaptureStartError)?.clientResult ?? .internalSubsystem
        }
    }
    
    /// Who is connected, for `macmonitor status` (``StreamService/AppCapture``).
    ///
    /// - Parameter reply: Receives, from `queue`, whether a Mac Monitor owns the event stream and whether it's
    ///   recording, and whether its capture holds Endpoint Security clients.
    public func captureState(_ reply: @escaping (SensorReport.App, Bool) -> Void) {
        queue.async { [self] in
            reply(SensorReport.App(connected: sink != nil, recording: capture?.isRecording ?? false), capture != nil)
        }
    }

    /// Tear down monitoring if `connection` was the event sink.
    ///
    /// - Parameter connection: A connection that was just invalidated.
    func detach(_ connection: NSXPCConnection) {
        guard let current = sink, current.connection === connection else { return }
        let counters = current.batcher.counters
        logger.log("""
            Mac Monitor disconnected after \(counters.delivered) of \(counters.enqueued) events \
            (\(counters.spooled) went through the spool, \(counters.dropped) were dropped, and \(counters.lost) were \
            in batches it never answered). Stopping capture.
            """)
        current.batcher.close()
        sink = nil
        capture?.stop()
        capture = nil
        muteSubscription = nil
        indicatorSubscription = nil
        /// Let a Mac Monitor that was refused (`.streamOwned`, `.tooManyClients`) claim the stream.
        released()
    }
    
    /// Batch events for Mac Monitor: in memory up to ``EventBatcher/Limits-swift.struct/app``'s limit, then spilled to
    /// an ``EventSpool`` file, so a stalled Mac Monitor can't grow a root process without bound. Nothing is dropped
    /// unless the spool is full too (``EventSpool/Limits-swift.struct``).
    ///
    /// - Parameter connection: The connection that claimed the event stream.
    /// - Returns: The batcher. Each batch sent also logs what Endpoint Security dropped since the last report.
    func makeBatcher(for connection: NSXPCConnection) -> EventBatcher {
        EventBatcher(queue: queue, limits: .app, overflow: .backlog { try EventSpool() },
                     delivery: EventBatcher.xpcDelivery(over: connection, label: "Mac Monitor"),
                     willSend: { [weak self] in self?.capture?.reportDrops() }, label: "Mac Monitor")
    }
}
