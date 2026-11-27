//
//  FakeFlowSocket.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
import os
@testable import SutroESFramework


// MARK: - A fake network statistics socket
/// The kernel's network statistics socket for a test: it hands the client the datagrams the test queues, records
/// every request, and answers a request with the errno the test sets.
final class FakeFlowSocket: FlowSocket {
    /// What the test controls.
    private struct State {
        var queued: [[UInt8]] = []
        var waiting = 0
        var reading: (queue: DispatchQueue, handler: () -> Void)?
        var isClosed = false
        var failing: ([UInt8]) -> Int32 = { _ in 0 }
    }

    let receiveBuffer: Int
    /// Every request sent, in order.
    let sent = Recorded<[UInt8]>()
    private let state = OSAllocatedUnfairLock(uncheckedState: State())

    /// - Parameter receiveBuffer: The receive buffer it says the kernel gave.
    init(receiveBuffer: Int = 4_194_304) {
        self.receiveBuffer = receiveBuffer
    }

    /// Is it closed?
    var isClosed: Bool { state.withLockUnchecked { $0.isClosed } }

    /// The bytes `pending()` reports.
    var waiting: Int {
        get { state.withLockUnchecked { $0.waiting } }
        set { state.withLockUnchecked { $0.waiting = newValue } }
    }

    /// Answer requests with an errno: 0 sends them.
    ///
    /// - Parameter failing: The errno for a request's bytes.
    func failRequests(_ failing: @escaping ([UInt8]) -> Int32) {
        state.withLockUnchecked { $0.failing = failing }
    }

    /// Queue datagrams, and tell the client they're waiting.
    ///
    /// - Parameters:
    ///   - datagrams: The datagrams.
    ///   - waking: Tell the client? Without it they wait for the client's next read.
    func deliver(_ datagrams: [[UInt8]], waking: Bool = true) {
        let reading = state.withLockUnchecked { state in
            state.queued += datagrams
            return state.reading
        }
        if waking, let reading { reading.queue.async(execute: reading.handler) }
    }

    /// The queries sent for sources, as their requests: not the first, which only sets the updates mode.
    var queries: [NStat.Request] {
        sent.all.filter { $0.count == 24 }.compactMap { request in
            request.withUnsafeBytes { NStat.Request(context: $0.integer(at: 0)) }
        }.filter { $0 != .mode }
    }

    /// Record a request, and answer it with the errno the test set.
    ///
    /// - Parameter bytes: The request.
    /// - Returns: The errno.
    func send(_ bytes: UnsafeRawBufferPointer) -> Int32 {
        let request = Array(bytes)
        sent.append(request)
        return state.withLockUnchecked { $0.failing(request) }
    }

    /// Hand over the next queued datagram, cut to the buffer.
    ///
    /// - Parameters:
    ///   - buffer: Where to put it.
    ///   - truncated: Set when it was cut.
    /// - Returns: Its length, or 0 when none is queued.
    func receive(into buffer: UnsafeMutableRawBufferPointer, truncated: inout Bool) -> Int {
        state.withLockUnchecked { state in
            guard !state.queued.isEmpty else { return 0 }
            let datagram = state.queued.removeFirst()
            truncated = datagram.count > buffer.count
            let length = min(datagram.count, buffer.count)
            buffer.copyBytes(from: datagram.prefix(length))
            return length
        }
    }

    /// - Returns: The bytes the test says are waiting.
    func pending() -> Int {
        waiting
    }

    /// Keep the handler, to call when the test delivers.
    ///
    /// - Parameters:
    ///   - queue: Where it runs.
    ///   - handler: The handler.
    func startReading(on queue: DispatchQueue, handler: @escaping () -> Void) {
        state.withLockUnchecked { $0.reading = (queue, handler) }
    }

    /// Note that it's closed.
    func close() {
        state.withLockUnchecked { $0.isClosed = true }
    }
}
