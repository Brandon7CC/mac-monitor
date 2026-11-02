//
//  CaptureSession+Statistics.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import EndpointSecurity
import OSLog


// MARK: - Statistics and drops
extension CaptureSession {
    /// The shortest time between two drop reports in the log, in nanoseconds.
    static let dropReportInterval: UInt64 = 1_000_000_000
    
    /// Each client's lifetime counters.
    ///
    /// - Returns: One entry per client, in ``EventClass/allCases`` order.
    public func statistics() -> [CaptureLaneStatistics] {
        lanes.map { lane in lane.statistics(subscribedEvents: subscribedEvents.filter(lane.serves).count) }
    }
    
    /// Messages the clients were handed while capture was open but not recording, and skipped, over the session's
    /// lifetime. Counted as each is turned away, so once ``isRecording`` is set, every message skipped before it is in.
    public var skippedMessages: UInt64 {
        lanes.reduce(0) { $0 + $1.skippedMessages }
    }
    
    /// The messages Endpoint Security dropped since the last call, for each client that lost any.
    ///
    /// - Returns: One report per client with new drops.
    public func takeDropReport() -> [CaptureDropReport] {
        lanes.compactMap { $0.takeDropReport() }
    }
    
    /// Log the messages Endpoint Security dropped since the last report, at most once every
    /// ``dropReportInterval``. Cheap enough to call whenever events are sent on.
    ///
    /// - Parameter now: The current uptime in nanoseconds.
    /// - Returns: The reports logged: none if there were no new drops, or the last report was too recent.
    @discardableResult
    public func reportDrops(now: UInt64 = DispatchTime.now().uptimeNanoseconds) -> [CaptureDropReport] {
        if let lastDropReport, now &- lastDropReport < Self.dropReportInterval { return [] }
        lastDropReport = now
        let reports = takeDropReport()
        for report in reports {
            Self.logger.fault("""
                \(self.label, privacy: .public): Endpoint Security dropped \(report.dropped) messages for the \
                \(report.eventClass.rawValue, privacy: .public) client, whose handler fell behind \
                (\(report.typeSummary, privacy: .public)).
                """)
        }
        return reports
    }
    
    /// Log each client's lifetime counters, and a fault for a client whose `global_seq_num` went backwards.
    func logStatistics() {
        for lane in statistics() {
            Self.logger.log("""
                \(self.label, privacy: .public): the \(lane.eventClass.rawValue, privacy: .public) client was handed \
                \(lane.messages) messages for \(lane.subscribedEvents) events. Endpoint Security dropped \
                \(lane.dropped) (in \(lane.gaps) gaps), and \(lane.serializationFailures) couldn't be serialized.
                """)
            guard lane.regressions > 0 else { continue }
            Self.logger.fault("""
                \(self.label, privacy: .public): Endpoint Security's global_seq_num repeated or went backwards \
                \(lane.regressions) times for the \(lane.eventClass.rawValue, privacy: .public) client, so its drop \
                counts can't be trusted.
                """)
        }
    }
}
