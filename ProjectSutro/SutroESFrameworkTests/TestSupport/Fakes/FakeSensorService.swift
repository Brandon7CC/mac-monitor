//
//  FakeSensorService.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
import os
@testable import SutroESFramework


// MARK: - A Security Extension for Mac Monitor
/// The Security Extension's side of Mac Monitor's connection, in the test process, as this build or 3.0.0 exports
/// it. It keeps `SensorService`'s rules: the first connection to `start` owns the event stream, only the owner
/// records, and only the owner, or anyone while nobody owns it, changes command line access. The real one stops
/// capture when the owner's connection closes, so this one notes it.
final class FakeSensorService: NSObject, NSXPCListenerDelegate, SensorProtocol {
    /// Which Security Extension it is.
    enum Release {
        /// 3.0.0, whose interface has no call added since (``SensorProtocolBeforeIndicators``).
        case v3_0
        /// This build's (``SensorXPC/sensorInterface``).
        case current
    }

    /// What it keeps. Requests arrive on each connection's own queue.
    private struct State {
        var owner: NSXPCConnection?
        var ownerClosed = false
        var starts = 0
        var access = CommandLineAccess.rootOnly
    }

    private let release: Release
    private let listener = NSXPCListener.anonymous()
    private let state = OSAllocatedUnfairLock<State>(uncheckedState: State())

    /// Start listening.
    ///
    /// - Parameter release: The interface to export.
    init(_ release: Release) {
        self.release = release
        super.init()
        listener.delegate = self
        listener.activate()
    }

    /// Where Mac Monitor connects.
    var endpoint: NSXPCListenerEndpoint {
        listener.endpoint
    }

    /// Has the connection that owns the event stream closed?
    var ownerClosed: Bool {
        state.withLockUnchecked { $0.ownerClosed }
    }

    /// How many handshakes came, from any connection.
    var starts: Int {
        state.withLockUnchecked { $0.starts }
    }

    /// Accept every connection, exporting the release's interface, and note when the owner's closes.
    ///
    /// - Parameters:
    ///   - listener: The anonymous listener.
    ///   - connection: The new connection.
    /// - Returns: Always `true`.
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = release == .v3_0
            ? NSXPCInterface(with: SensorProtocolBeforeIndicators.self) : SensorXPC.sensorInterface
        connection.exportedObject = self
        connection.invalidationHandler = { [weak self, weak connection] in
            self?.state.withLockUnchecked { state in
                if state.owner != nil, state.owner === connection { state.ownerClosed = true }
            }
        }
        connection.activate()
        return true
    }

    /// Does the connection delivering this message own the event stream?
    private var callerOwns: Bool {
        let caller = NSXPCConnection.current()
        return state.withLockUnchecked { $0.owner != nil && $0.owner === caller }
    }

    // MARK: SensorProtocol
    /// The first caller owns the event stream; any other is refused.
    func start(recording: Bool, reply: @escaping (NewClientResult) -> Void) {
        let caller = NSXPCConnection.current()
        reply(state.withLockUnchecked { state in
            state.starts += 1
            if state.owner == nil { state.owner = caller }
            return state.owner === caller ? .success : .streamOwned
        })
    }

    /// `true` only for the owner.
    func setRecording(_ enabled: Bool, reply: @escaping (Bool) -> Void) {
        reply(callerOwns)
    }

    /// The level, to any caller.
    func commandLineAccess(reply: @escaping (String) -> Void) {
        reply(state.withLockUnchecked { $0.access.rawValue })
    }

    /// Changed by the owner, or by anyone while nobody owns the event stream.
    func setCommandLineAccess(_ access: String, reply: @escaping (Int) -> Void) {
        let caller = NSXPCConnection.current()
        reply(state.withLockUnchecked { state in
            guard let level = CommandLineAccess(rawValue: access) else { return CommandLineAccessChange.invalid }
            guard MuteAccess.controlsStream(caller, owner: state.owner) else { return .streamOwned }
            state.access = level
            return .done
        }.rawValue)
    }

    /// The shipped indicators, readable by any caller.
    func indicators(_ request: Data, reply: @escaping (Data) -> Void) {
        reply(IndicatorReply(status: .ok, indicators: Indicator.defaults, access: .read).encoded())
    }

    /// No subscriptions.
    func eventSubscriptions(reply: @escaping ([String]) -> Void) { reply([]) }
    /// Refused.
    func setSubscription(_ event: String, enabled: Bool, reply: @escaping (Bool) -> Void) { reply(false) }
    /// Nothing useful: no test asks.
    func mutes(_ request: Data, reply: @escaping (Data) -> Void) { reply(Data()) }
    /// No mutes.
    func appleMuteSet(reply: @escaping ([String]) -> Void) { reply([]) }
    /// No answer.
    func checkForUpdate(reply: @escaping (Data?) -> Void) { reply(nil) }
    /// Refused.
    func installUpdate(reply: @escaping (String?) -> Void) { reply(UpdateFailure.streamOwned.rawValue) }
    /// Refused.
    func changeCommandLineTool(action: String, tool: String, expected: String, authorization: Data,
                               reply: @escaping (Int) -> Void) {
        reply(CommandLineToolLinker.Outcome.notAuthorized.rawValue)
    }
}


// MARK: - A silent agent
/// Mac Monitor's side of the connection, for a test that sends requests: it takes every batch and ignores an update's
/// progress.
final class SilentAgent: NSObject, AppAgentProtocol {
    /// Take a batch of events and reply at once.
    func receive(events: [Data], reply: @escaping () -> Void) { reply() }
    /// Ignore an update's progress.
    func updateProgress(_ progress: Data) {}
}
