//
//  SensorService+Protocol.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - SensorProtocol
extension SensorService: SensorProtocol {
    /// Claim the event stream and start capture, or redo the owner's handshake. A connection that doesn't own the
    /// stream while another does gets `.streamOwned`, and a start Endpoint Security refuses leaves no owner.
    ///
    /// - Parameters:
    ///   - recording: Whether capture records events.
    ///   - reply: `.success`, or why not.
    public func start(recording: Bool, reply: @escaping (NewClientResult) -> Void) {
        /// Must be read on the thread delivering the message, before hopping queues.
        guard let caller = NSXPCConnection.current() else {
            logger.fault("start(recording:reply:) was called outside of an XPC message!")
            return reply(.internalSubsystem)
        }
        
        queue.async { [self] in
            if let owner = sink, owner.connection !== caller {
                logger.error("""
                    Refusing start from a second Mac Monitor connection (pid \(caller.processIdentifier)). \
                    A connection from pid \(owner.connection.processIdentifier) owns the event stream.
                    """)
                return reply(.streamOwned)
            }
            let claims = sink == nil
            if claims { sink = Sink(connection: caller, batcher: makeBatcher(for: caller)) }
            
            let result = startCapture()
            /// A handshake Endpoint Security refused never leaves an owner without capture.
            if result != .success, claims {
                sink?.batcher.close()
                sink = nil
            }
            capture?.isRecording = recording
            logger.log("Mac Monitor connected (recording: \(recording)). Endpoint Security result: \(result.rawValue)")
            reply(result)
        }
    }
    
    /// Start or stop recording. Only the owner may.
    ///
    /// - Parameters:
    ///   - enabled: Whether to record.
    ///   - reply: `true` if capture runs for the owner.
    public func setRecording(_ enabled: Bool, reply: @escaping (Bool) -> Void) {
        performForOwner(refusing: false, reply) { [self] in
            capture?.isRecording = enabled
            return capture != nil
        }
    }
    
    /// The events and field filters capture subscribes to, or will once it starts. Any caller may ask.
    ///
    /// - Parameter reply: Event names and ``FieldFilter`` wire names, sorted.
    public func eventSubscriptions(reply: @escaping ([String]) -> Void) {
        perform(reply) { [self] in
            Set((capture?.subscribedEvents ?? subscriptions).map { eventTypeToString(from: $0) })
                .union((capture?.fieldFilters ?? fieldFilters).map(\.rawValue)).sorted()
        }
    }
    
    /// Subscribe to an event, or turn on a field filter, or the reverse. Only the owner may, while capture runs.
    ///
    /// - Parameters:
    ///   - event: An event name or a ``FieldFilter`` wire name.
    ///   - enabled: Whether to subscribe.
    ///   - reply: `true` if capture took the change.
    public func setSubscription(_ event: String, enabled: Bool, reply: @escaping (Bool) -> Void) {
        performForOwner(refusing: false, reply) { [self] in
            if let filter = FieldFilter(rawValue: event) {
                guard let capture, capture.setFieldFilter(filter, enabled: enabled) else { return false }
                fieldFilters = capture.fieldFilters
                return true
            }
            guard let capture, capture.setSubscription(eventStringToType(from: event), enabled: enabled) else {
                return false
            }
            subscriptions = capture.subscribedEvents
            return true
        }
    }
    
    /// Endpoint Security's default mutes. Any caller may ask.
    ///
    /// - Parameter reply: ``ESMutedPath`` JSON, sorted.
    public func appleMuteSet(reply: @escaping ([String]) -> Void) {
        perform(reply) { [self] in appleDefaultMutes.sorted() }
    }
    
    /// Answer a saved mute set request (``MuteAccess/app(_:owner:)``).
    ///
    /// - Parameters:
    ///   - request: A JSON encoded ``MuteRequest``.
    ///   - reply: A JSON encoded ``MuteReply``.
    public func mutes(_ request: Data, reply: @escaping (Data) -> Void) {
        /// Must be read on the thread delivering the message, before hopping queues. No connection means nothing may
        /// change.
        let caller = NSXPCConnection.current()
        queue.async { [self] in
            /// Any user's Mac Monitor may change the saved set. Like `installUpdate`, it may while nobody owns the
            /// event stream, and while someone does, only they may. Every Mac Monitor may list it.
            let access = MuteAccess.app(caller, owner: sink?.connection)
            savedMutes.handle(request, access: access, caller: "Mac Monitor (pid \(caller?.processIdentifier ?? 0))",
                              reply: reply)
        }
    }
    
    /// Answer an indicator set request, by the saved mute set's rule.
    ///
    /// - Parameters:
    ///   - request: A JSON encoded ``IndicatorRequest``.
    ///   - reply: A JSON encoded ``IndicatorReply``.
    public func indicators(_ request: Data, reply: @escaping (Data) -> Void) {
        /// Read on the thread delivering the message, as `mutes(_:reply:)` does, and decided by the same rule.
        let caller = NSXPCConnection.current()
        queue.async { [self] in
            let access = MuteAccess.app(caller, owner: sink?.connection)
            savedIndicators.handle(request, access: access,
                                   caller: "Mac Monitor (pid \(caller?.processIdentifier ?? 0))", reply: reply)
        }
    }
    
    /// Check for a newer release. Any caller may ask. Network work runs on the updater's own tasks so it never
    /// blocks `queue`.
    ///
    /// - Parameter reply: A JSON encoded ``UpdateCheck``.
    public func checkForUpdate(reply: @escaping (Data?) -> Void) {
        updates.check(reply: reply)
    }
    
    /// Link or unlink `macmonitor` in `/usr/local/bin` once Settings' authorization is approved.
    ///
    /// - Parameters:
    ///   - action: ``CommandLineToolLinker``'s action.
    ///   - tool: The tool inside Mac Monitor.
    ///   - expected: The link's value Settings saw, or empty for none: the change happens only if it still matches.
    ///   - authorization: An external form of the caller's authorization.
    ///   - reply: A ``CommandLineToolLinker/Outcome`` raw value.
    public func changeCommandLineTool(action: String, tool: String, expected: String, authorization: Data,
                                      reply: @escaping (Int) -> Void) {
        // Off `queue` since the signature check reads from disk.
        DispatchQueue.global(qos: .userInitiated).async { [logger] in
            let (outcome, plan) = CommandLineToolLinker().handle(action: action, tool: tool, expected: expected) {
                CommandLineToolAuthorization.isApproved(authorization)
            }
            if let plan {
                logger.log("""
                    \(action, privacy: .public) \(plan.linkPath, privacy: .public) \
                    (\(plan.tool, privacy: .public)): \(String(describing: outcome), privacy: .public)
                    """)
            } else {
                logger.error("""
                    Refused to \(action, privacy: .public) the command line tool: \
                    \(String(describing: outcome), privacy: .public).
                    """)
            }
            reply(outcome.rawValue)
        }
    }

    /// Who may use `macmonitor` without `sudo`. Any caller may ask.
    ///
    /// - Parameter reply: A ``CommandLineAccess`` raw value.
    public func commandLineAccess(reply: @escaping (String) -> Void) {
        reply(commandLineAccess.access.rawValue)
    }
    
    /// Change who may use `macmonitor` without `sudo`: the owner, or anyone while nobody owns the event stream.
    ///
    /// - Parameters:
    ///   - access: A ``CommandLineAccess`` raw value.
    ///   - reply: A ``CommandLineAccessChange`` raw value.
    public func setCommandLineAccess(_ access: String, reply: @escaping (Int) -> Void) {
        /// Read on the thread delivering the message, as `mutes(_:reply:)` does.
        let caller = NSXPCConnection.current()
        queue.async { [self] in
            guard let level = CommandLineAccess(rawValue: access) else {
                return reply(CommandLineAccessChange.invalid.rawValue)
            }
            /// The same rule as the saved mute set: while nobody owns the event stream, or only its owner.
            guard caller != nil, MuteAccess.controlsStream(caller, owner: sink?.connection) else {
                return reply(CommandLineAccessChange.streamOwned.rawValue)
            }
            let outcome = commandLineAccess.change(to: level)
            logger.log("""
                Command line access \(level.rawValue, privacy: .public): \
                \(String(describing: outcome), privacy: .public)
                """)
            reply(outcome.rawValue)
        }
    }
    
    /// Install the latest release: the owner, or anyone while nobody owns the event stream.
    ///
    /// - Parameter reply: `nil` if the update was installed, else an ``UpdateFailure`` raw value.
    public func installUpdate(reply: @escaping (String?) -> Void) {
        /// Read on the thread delivering the message, as `mutes(_:reply:)` does.
        let caller = NSXPCConnection.current()
        queue.async { [self] in
            /// Any user's Mac Monitor may install, since only a verified release is installed. It may while nobody
            /// owns the stream (e.g. one launched with `--deactivate-security-extension`). While someone does, only
            /// they may.
            guard sink == nil || owns(caller) else { return reply(UpdateFailure.streamOwned.rawValue) }
            /// Progress goes to the Mac Monitor that asked, in order, ahead of the reply.
            let agent = caller?.remoteObjectProxy as? AppAgentProtocol
            updates.install(progress: { progress in
                if let data = try? JSONEncoder().encode(progress) { agent?.updateProgress(data) }
            }, reply: { reply($0?.rawValue) })
        }
    }
}
