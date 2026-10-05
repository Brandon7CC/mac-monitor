//
//  StreamClient.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import os


// MARK: - Stream client
/// `macmonitor`'s connection to the Security Extension (command line context).
///
/// It calls ``StreamProtocol`` and exports the ``StreamReaderProtocol`` receiver that takes the stream's batches. The
/// receiver is set before the connection is activated, so a batch that beats the stream request's reply isn't lost.
/// The live connection looks the service up in the system domain (`.privileged`, so a same-named service in the user's
/// session can't stand in) and requires the Security Extension's code signature.
///
/// There's no reconnecting: a connection that goes away after the first answer means the Security Extension stopped.
public final class StreamClient {
    /// The connection.
    public let connection: NSXPCConnection
    /// Has the Security Extension answered anything yet?
    private let answered = OSAllocatedUnfairLock(initialState: false)
    
    /// The connection to the live Security Extension.
    ///
    /// - Returns: A client whose connection isn't activated yet.
    public static func live() -> StreamClient {
        StreamClient(connection: NSXPCConnection(machServiceName: SensorXPC.machServiceName, options: .privileged),
                     requirement: SensorXPC.sensorRequirement)
    }
    
    /// - Parameters:
    ///   - connection: A connection to the Security Extension's service, not yet activated.
    ///   - requirement: The code signing requirement the Security Extension must satisfy, or `nil` for none (an
    ///     in-process test service).
    public init(connection: NSXPCConnection, requirement: String?) {
        self.connection = connection
        connection.remoteObjectInterface = SensorXPC.streamInterface
        connection.exportedInterface = SensorXPC.streamReaderInterface
        if let requirement { connection.setCodeSigningRequirement(requirement) }
    }
    
    /// Export the receiver and activate the connection.
    ///
    /// - Parameters:
    ///   - receiver: Takes the stream's batches, and what to tell the user while it streams.
    ///   - lost: Called, on any thread, if the connection goes away after the Security Extension answered: it
    ///     stopped. A connection that never worked reports through the request that found out.
    public func activate(receiving receiver: StreamReaderProtocol, lost: @escaping (CommandLineFailure) -> Void) {
        connection.exportedObject = receiver
        let ended: () -> Void = { [answered] in
            if answered.withLock({ $0 }) { lost(.stopped) }
        }
        connection.interruptionHandler = ended
        connection.invalidationHandler = ended
        connection.activate()
    }
    
    /// Send a stream request.
    ///
    /// - Parameters:
    ///   - request: The request.
    ///   - timeout: How long to wait for the answer, or `nil` to wait as long as it takes.
    ///   - completion: Called once, on any thread: the answer, or why there's none.
    public func send(_ request: StreamRequest, timeout: DispatchTimeInterval?,
                     completion: @escaping (Result<StreamReply, CommandLineFailure>) -> Void) {
        call(timeout: timeout, decode: StreamReply.decode, completion: completion) { sensor, reply in
            sensor.perform(request.encoded(), reply: reply)
        }
    }
    
    /// Send a mute request.
    ///
    /// - Parameters:
    ///   - request: The request.
    ///   - timeout: How long to wait for the answer.
    ///   - completion: Called once, on any thread: the answer, or why there's none.
    public func send(_ request: MuteRequest, timeout: DispatchTimeInterval,
                     completion: @escaping (Result<MuteReply, CommandLineFailure>) -> Void) {
        call(timeout: timeout, decode: MuteReply.decode, completion: completion) { sensor, reply in
            sensor.mutes(request.encoded(), reply: reply)
        }
    }
    
    /// Make one call on the Security Extension and decode its answer.
    ///
    /// - Parameters:
    ///   - timeout: How long to wait for the answer, or `nil` to wait as long as it takes.
    ///   - decode: Reads the answer.
    ///   - completion: Called once, on any thread: the answer, or why there's none.
    ///   - invoke: Makes the call on the proxy.
    private func call<Reply>(timeout: DispatchTimeInterval?, decode: @escaping (Data) -> Reply?,
                             completion: @escaping (Result<Reply, CommandLineFailure>) -> Void,
                             invoke: (StreamProtocol, @escaping (Data) -> Void) -> Void) {
        let finish = Self.once(completion)
        let proxy = connection.remoteObjectProxyWithErrorHandler { [answered] error in
            finish(.failure(CommandLineFailure.connection(error, started: answered.withLock { $0 })))
        }
        if let timeout {
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { finish(.failure(.noAnswer)) }
        }
        guard let sensor = proxy as? StreamProtocol else {
            return finish(.failure(CommandLineFailure(.software, "The connection's proxy isn't a StreamProtocol.")))
        }
        invoke(sensor) { [answered] data in
            answered.withLock { $0 = true }
            guard let reply = decode(data) else {
                let unreadable = CommandLineFailure(.unavailable, "The Security Extension's answer didn't read.")
                return finish(.failure(unreadable))
            }
            finish(.success(reply))
        }
    }
    
    /// Close the connection. The Security Extension closes the stream.
    public func invalidate() {
        connection.invalidate()
    }
    
    /// A completion that only runs the first time it's called, from any thread.
    ///
    /// - Parameter completion: The completion.
    /// - Returns: The guarded completion.
    static func once<Value>(_ completion: @escaping (Value) -> Void) -> (Value) -> Void {
        let called = OSAllocatedUnfairLock(initialState: false)
        return { value in
            guard !called.withLock({ called in defer { called = true }; return called }) else { return }
            completion(value)
        }
    }
}
