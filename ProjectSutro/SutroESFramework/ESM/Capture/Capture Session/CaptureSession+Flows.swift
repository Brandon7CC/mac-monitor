//
//  CaptureSession+Flows.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Network flows
/// A session records network flows on its network lane (``FlowLane``), which it registers with the network
/// statistics client while it subscribes to `new_flow` or `flow_closed`. The client's socket is open while any
/// session's lane is registered, so nothing is read while no session records flows.
extension CaptureSession {
    /// Subscribe to, or unsubscribe from, a network flow event.
    ///
    /// - Parameters:
    ///   - event: The flow event.
    ///   - enabled: `true` to subscribe, `false` to unsubscribe.
    /// - Returns: `false` after ``stop()``, for a session that can't record flows, or when the client couldn't open its
    ///   socket (``flowProblem``). The event isn't subscribed then.
    @discardableResult
    public func setSubscription(_ event: MacMonitorEvent, enabled: Bool) -> Bool {
        guard flowLane != nil, !isStopped else { return false }
        if !enabled {
            subscribedEvents.removeAll { $0 == event.type }
        } else if !subscribedEvents.contains(event.type) {
            subscribedEvents.append(event.type)
        }
        return updateFlows()
    }

    /// Keep a URL's path in the flows recorded from now on, or end the URL at its host and port.
    ///
    /// - Parameter keeps: Keep the path?
    /// - Returns: `false` for a session that can't record flows, or has stopped.
    @discardableResult
    public func setRecordsURLPaths(_ keeps: Bool) -> Bool {
        guard let flowLane, !isStopped else { return false }
        flowLane.setRecordsURLPaths(keeps)
        Self.logger.log("\(self.label, privacy: .public): URL paths \(keeps ? "on" : "off", privacy: .public).")
        return true
    }

    /// Why the session can't record network flows: the client's reason, the last time it couldn't open its socket.
    public var flowProblem: String? {
        flowLane?.problem
    }

    /// The network lane's lifetime counters, apart from the Endpoint Security clients'.
    ///
    /// - Returns: The counters, or `nil` for a session that never recorded flows.
    public func flowStatistics() -> FlowLaneStatistics? {
        guard let flowLane, flowLane.wasRegistered else { return nil }
        return flowLane.statistics()
    }

    /// Register the network lane while the session subscribes to a flow event and hasn't stopped, and unregister it
    /// otherwise. A registration the client refuses takes the flow events out of the subscriptions.
    ///
    /// - Returns: `false` when the client couldn't open its socket.
    @discardableResult
    func updateFlows() -> Bool {
        guard let flowLane else { return true }
        let events = Set(subscribedEvents.compactMap(MacMonitorEvent.init))
        let wanted = !events.isEmpty && !isStopped
        /// Before registering, so the first records are taken.
        flowLane.setSubscribed(wanted ? events : [])
        guard wanted else {
            flowLane.unregister()
            return true
        }
        guard flowLane.register() else {
            flowLane.setSubscribed([])
            subscribedEvents.removeAll { MacMonitorEvent($0) != nil }
            Self.logger.error("""
                \(self.label, privacy: .public): network flows can't be recorded: \
                \(flowLane.problem ?? "", privacy: .public)
                """)
            return false
        }
        return true
    }

    /// Deliver every flow the client has read so far, then close the network lane, so a stopping session keeps what
    /// was captured up to now and nothing after. Call on the session's queue, after the Endpoint Security clients
    /// have synced.
    ///
    /// - Parameter completion: Called once, from any queue.
    func drainFlows(then completion: @escaping () -> Void) {
        guard let flowLane, flowLane.isRegistered else { return completion() }
        flowLane.drain(then: completion)
    }

    /// Unregister the network lane, which ``stop()`` has closed, and wait until a deadline for the flow being built.
    /// One still being built then is dropped. Call from ``stop()``.
    ///
    /// - Parameter deadline: When to stop waiting.
    func stopFlows(by deadline: DispatchTime) {
        guard let flowLane else { return }
        flowLane.unregister()
        guard !flowLane.waitUntilIdle(until: deadline) else { return }
        Self.logger.fault("""
            \(self.label, privacy: .public): the network lane was still building a flow's event at the deadline. \
            Dropped it.
            """)
    }
}
