//
//  RawMessageFixture+RemoteThreadCreate.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - remote_thread_create events
extension RawMessageFixture {
    /// The bytes 0, 1, 2 and so on, wrapping at 256: a thread state's synthetic contents.
    ///
    /// - Parameter count: How many bytes.
    /// - Returns: The bytes.
    static func bytes(_ count: Int) -> [UInt8] {
        (0..<count).map { UInt8(truncatingIfNeeded: $0) }
    }
    
    /// A thread state whose bytes live as long as the fixture.
    ///
    /// - Parameters:
    ///   - flavor: The state's flavor.
    ///   - bytes: The bytes at `data`, or `nil` for a `NULL` `data`.
    ///   - size: The token's `size`, or `nil` for the number of bytes.
    /// - Returns: The thread state.
    func threadState(flavor: Int32 = 6, bytes: [UInt8]?, size: Int? = nil) -> es_thread_state_t {
        guard let bytes else {
            return es_thread_state_t(flavor: flavor, state: es_token_t(size: size ?? 0, data: nil))
        }
        let memory = allocate(UInt8.self, count: max(bytes.count, 1))
        memory.update(from: bytes, count: bytes.count)
        return es_thread_state_t(flavor: flavor, state: es_token_t(size: size ?? bytes.count, data: memory))
    }
    
    /// Place a `remote_thread_create` event in the message.
    ///
    /// - Parameters:
    ///   - target: The process the thread was created in, or `nil` for `/bin/sleep`.
    ///   - threadState: The event's thread state, or `nil` for a `NULL` `thread_state` (`thread_create`).
    func remoteThreadCreate(target: UnsafeMutablePointer<es_process_t>? = nil, threadState: es_thread_state_t?) {
        let event = allocate(es_event_remote_thread_create_t.self)
        event.pointee.target = target ?? process(path: "/bin/sleep", signingID: "com.apple.sleep", pid: 4243)
        event.pointee.thread_state = threadState.map { pointer($0) }
        message.pointee.event.remote_thread_create = event.pointee
    }
    
    /// Place the `remote_thread_create` event of an eslogger record in the message: its target, and its thread
    /// state's flavor with no bytes, since eslogger writes none.
    ///
    /// - Parameter record: The record.
    /// - Returns: `false` if the record holds another event.
    func fillRemoteThreadCreate(eslogger record: [String: Any]) -> Bool {
        guard let object = (record["event"] as? [String: Any])?["remote_thread_create"] as? [String: Any],
              let target = object["target"] as? [String: Any] else {
            return false
        }
        let state = object["thread_state"] as? [String: Any]
        remoteThreadCreate(target: process(eslogger: target), threadState: state.map {
            threadState(flavor: ($0["flavor"] as? NSNumber)?.int32Value ?? 0, bytes: nil)
        })
        return true
    }
}
