//
//  SensorSupport.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Sensor support
/// Does the Security Extension running now answer a request added after 3.0? It says so itself, once per handshake.
///
/// A Security Extension older than 3.1 has no `indicators`, `commandLineAccess` or `setCommandLineAccess` call, and
/// NSXPC closes the connection that sends a message its peer doesn't know. On Mac Monitor's own connection that would
/// end the event stream, and the handshake after it would ask again. So the first such request after each handshake
/// waits for the same kind of request sent on a connection of its own (``SensorClient/probe(caller:_:completion:)``):
/// a reply means yes, and none means no, until ``forget()``. Nothing is read from a version string, which every build
/// reports as its marketing version, released or not.
///
/// ``XPCProtocolSnapshotTests`` fails for a request added to ``SensorProtocol`` until it says how it's guarded.
///
/// **Threading:** use it on the main queue. The probe replies there.
public final class SensorSupport {
    /// Asks the Security Extension, and calls back on the main queue with whether it answered.
    public typealias Probe = (_ answered: @escaping (Bool) -> Void) -> Void

    private let probe: Probe
    /// The last answer, or `nil` until the probe answers after a ``forget()``.
    public private(set) var answers: Bool?
    /// What waits for the probe in flight.
    private var waiting: [(Bool) -> Void] = []
    /// Counts ``forget()``s, so an answer asked for before one isn't kept.
    private var generation = 0

    /// - Parameter probe: Asks the Security Extension running now. Nothing is asked until ``whenKnown(_:)``.
    public init(probe: @escaping Probe) {
        self.probe = probe
    }

    /// Call `then` with whether the Security Extension answers, asking it first when that isn't known. Calls that
    /// arrive while it's asked share the one probe.
    ///
    /// - Parameter then: Called with the answer: at once when it's known, else on the main queue.
    public func whenKnown(_ then: @escaping (Bool) -> Void) {
        if let answers { return then(answers) }
        waiting.append(then)
        guard waiting.count == 1 else { return }
        let asked = generation
        probe { [self] answered in
            if asked == generation { answers = answered }
            let waited = waiting
            waiting = []
            waited.forEach { $0(answered) }
        }
    }

    /// Send a request once the Security Extension has said it answers: one that doesn't is sent nothing, and one
    /// that stops answering is asked again before the next request.
    ///
    /// - Parameters:
    ///   - request: Sends the request on Mac Monitor's own connection, and calls back on the main queue with the
    ///     reply, or `nil` for none.
    ///   - completion: Called on the main queue with the reply, or `nil` if there was none or nothing was sent.
    public func send<Reply>(_ request: @escaping (_ reply: @escaping (Reply?) -> Void) -> Void,
                            completion: @escaping (Reply?) -> Void) {
        whenKnown { [self] answers in
            guard answers else { return DispatchQueue.main.async { completion(nil) } }
            request { [self] reply in
                if reply == nil { forget() }
                completion(reply)
            }
        }
    }

    /// Ask again before the next request: the Security Extension finished a handshake, so it may be another
    /// version, or a request got no reply.
    public func forget() {
        answers = nil
        generation += 1
    }
}
