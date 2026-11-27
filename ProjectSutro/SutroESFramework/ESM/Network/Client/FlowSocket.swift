//
//  FlowSocket.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - The socket
/// The kernel's network statistics socket, as the client uses it. Tests give a fake.
protocol FlowSocket: AnyObject {
    /// The receive buffer the kernel gave, in bytes.
    var receiveBuffer: Int { get }

    /// Write one request.
    ///
    /// - Parameter bytes: The request.
    /// - Returns: 0, or the errno.
    func send(_ bytes: UnsafeRawBufferPointer) -> Int32

    /// Read one datagram without waiting.
    ///
    /// - Parameters:
    ///   - buffer: Where to read it.
    ///   - truncated: Set when the datagram didn't fit, and was cut short.
    /// - Returns: Its length, 0 when none is waiting, or `-errno`.
    func receive(into buffer: UnsafeMutableRawBufferPointer, truncated: inout Bool) -> Int

    /// How many bytes are waiting.
    ///
    /// - Returns: The count.
    func pending() -> Int

    /// Call a handler whenever a datagram is waiting.
    ///
    /// - Parameters:
    ///   - queue: Where the handler runs.
    ///   - handler: The handler.
    func startReading(on queue: DispatchQueue, handler: @escaping () -> Void)

    /// Stop reading, and close.
    func close()
}


/// Why the socket couldn't be opened.
struct FlowSocketError: Error, CustomStringConvertible {
    let code: Int32

    /// The error's text and number.
    var description: String {
        "\(String(cString: strerror(code))) (errno \(code))"
    }
}


/// The live socket, connected without blocking, with a 4 MB receive buffer, and read from a dispatch source.
final class KernelFlowSocket: FlowSocket {
    /// The receive buffer asked for. A full buffer loses sockets, and on macOS 13 and 14 hides them from older
    /// clients too.
    static let requestedBuffer = 4_194_304

    let receiveBuffer: Int
    private let descriptor: Int32
    private var reader: DispatchSourceRead?
    private var isClosed = false

    /// Open and connect.
    ///
    /// - Throws: ``FlowSocketError`` when the socket can't be opened or connected.
    init() throws {
        var applied: Int32 = 0
        let result = nstat_connect(Int32(Self.requestedBuffer), &applied)
        guard result >= 0 else { throw FlowSocketError(code: -result) }
        (descriptor, receiveBuffer) = (result, Int(applied))
    }

    /// `send`. The kernel handles a request during the call, and fails it only when it couldn't queue the error
    /// that answers it either.
    ///
    /// - Parameter bytes: The request.
    /// - Returns: 0, or the errno.
    func send(_ bytes: UnsafeRawBufferPointer) -> Int32 {
        Darwin.send(descriptor, bytes.baseAddress, bytes.count, 0) == bytes.count ? 0 : errno
    }

    /// `recvmsg` without waiting, which says when a datagram was cut short.
    ///
    /// - Parameters:
    ///   - buffer: Where to read it.
    ///   - truncated: Set when the datagram didn't fit.
    /// - Returns: Its length, 0 when none is waiting, or `-errno`.
    func receive(into buffer: UnsafeMutableRawBufferPointer, truncated: inout Bool) -> Int {
        var vector = iovec(iov_base: buffer.baseAddress, iov_len: buffer.count)
        var header = msghdr()
        let length = withUnsafeMutablePointer(to: &vector) { vector in
            header.msg_iov = vector
            header.msg_iovlen = 1
            return recvmsg(descriptor, &header, MSG_DONTWAIT)
        }
        guard length >= 0 else { return errno == EAGAIN ? 0 : -Int(errno) }
        truncated = header.msg_flags & MSG_TRUNC != 0
        return length
    }

    /// `FIONREAD`.
    ///
    /// - Returns: How many bytes are waiting.
    func pending() -> Int {
        max(Int(nstat_pending(descriptor)), 0)
    }

    /// A dispatch read source on the socket, whose cancel closes it.
    ///
    /// - Parameters:
    ///   - queue: Where the handler runs.
    ///   - handler: The handler.
    func startReading(on queue: DispatchQueue, handler: @escaping () -> Void) {
        let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
        let descriptor = descriptor
        source.setEventHandler(handler: handler)
        source.setCancelHandler { Darwin.close(descriptor) }
        reader = source
        source.resume()
    }

    /// Cancel the read source, which closes the socket, once.
    func close() {
        guard !isClosed else { return }
        isClosed = true
        if let reader { reader.cancel() } else { Darwin.close(descriptor) }
        reader = nil
    }
}
