//
//  FlowDescriptor.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - A source descriptor
/// A source's descriptor in a message, read at its layout's offsets. It doesn't own the bytes, so read it during the
/// call that has the message.
struct FlowDescriptor {
    /// The descriptor's bytes.
    let bytes: UnsafeRawBufferPointer
    let layout: DescriptorLayout

    /// - Parameters:
    ///   - message: A whole message.
    ///   - offset: Where its descriptor starts.
    ///   - layout: The descriptor's layout.
    init?(_ message: UnsafeRawBufferPointer, at offset: Int, layout: DescriptorLayout) {
        guard offset + layout.size <= message.count else { return nil }
        bytes = UnsafeRawBufferPointer(rebasing: message[offset..<offset + layout.size])
        self.layout = layout
    }

    /// The unique IDs of the socket's last user and of the process it acts for.
    var upid: UInt64 { bytes.integer(at: layout.upid) }
    var eupid: UInt64 { bytes.integer(at: layout.eupid) }
    /// The pids of the socket's last user and of the process it acts for, which is 0 or the same when it acts
    /// for none.
    var pid: Int32 { bytes.integer(at: layout.pid) }
    var epid: Int32 { bytes.integer(at: layout.epid) }
    /// When the socket was made, and when the descriptor was copied, in `mach_continuous_time` ticks.
    var start: UInt64 { bytes.integer(at: layout.start) }
    var timestamp: UInt64 { bytes.integer(at: layout.timestamp) }
    /// A TCP socket's state (`TCPS_*`). `nil` for UDP.
    var state: UInt32? { layout.state.map { bytes.integer(at: $0) } }
    /// The interface's properties, and from Darwin 23 the flow's direction.
    var ifnetProperties: UInt32 { bytes.integer(at: layout.ifnetProperties) }
    var local: FlowAddress { FlowAddress(bytes, at: layout.local) }
    var remote: FlowAddress { FlowAddress(bytes, at: layout.remote) }

    /// The process's name, up to its NUL.
    ///
    /// - Returns: The name.
    func processName() -> String {
        let name = UnsafeRawBufferPointer(rebasing: bytes[layout.pname..<layout.pname + 64])
        return String(decoding: name.prefix { $0 != 0 }, as: UTF8.self)
    }

    /// Does it look like a descriptor? Its name ends within its 64 bytes with no control character before, and each
    /// address is empty, IPv4 or IPv6, with the length that goes with it.
    var isPlausible: Bool {
        let name = bytes[layout.pname..<layout.pname + 64]
        guard let end = name.firstIndex(of: 0), !name[..<end].contains(where: { $0 < 0x20 || $0 == 0x7F }) else {
            return false
        }
        return [layout.local, layout.remote].allSatisfy { offset in
            let length = bytes[offset], family = bytes[offset + 1]
            return (family == 0 && length == 0) || (Int32(family) == AF_INET && length == 16)
                || (Int32(family) == AF_INET6 && length == 28)
        }
    }
}


// MARK: - An address
/// An address and port from a descriptor's `sockaddr`, kept without allocating.
struct FlowAddress: Hashable {
    /// `AF_INET`, `AF_INET6`, or 0 when there's none.
    let family: UInt8
    /// The port, in host order.
    let port: UInt16
    /// The address's bytes in memory order. An IPv4 address is in the first four.
    let bytes: SIMD2<UInt64>

    /// - Parameters:
    ///   - descriptor: A descriptor's bytes.
    ///   - offset: Where its `sockaddr` is.
    init(_ descriptor: UnsafeRawBufferPointer, at offset: Int) {
        family = descriptor.integer(at: offset + 1)
        port = descriptor.integer(at: offset + 2, as: UInt16.self).byteSwapped
        switch Int32(family) {
        case AF_INET: bytes = SIMD2(UInt64(descriptor.integer(at: offset + 4, as: UInt32.self)), 0)
        case AF_INET6: bytes = SIMD2(descriptor.integer(at: offset + 8), descriptor.integer(at: offset + 16))
        default: bytes = .zero
        }
    }

    /// Is it an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`)?
    private var isMapped: Bool {
        Int32(family) == AF_INET6 && bytes[0] == 0 && UInt32(truncatingIfNeeded: bytes[1]) == 0xFFFF_0000
    }

    /// The IPv4 address's bytes, of an IPv4 or an IPv4-mapped address.
    private var ipv4: UInt64? {
        Int32(family) == AF_INET ? bytes[0] : isMapped ? bytes[1] >> 32 : nil
    }

    /// Is anything known of it? It's IPv4 or IPv6, with a port or an address that isn't zero.
    var isKnown: Bool {
        (Int32(family) == AF_INET || Int32(family) == AF_INET6) && (port != 0 || bytes != .zero)
    }

    /// Is it a loopback address, in `127.0.0.0/8` or `::1`?
    var isLoopback: Bool {
        if let ipv4 { return ipv4 & 0xFF == 127 }
        return Int32(family) == AF_INET6 && bytes == SIMD2(0, 1 << 56)
    }

    /// The address as text, with no scope. An IPv4-mapped one is written as IPv4, so it matches the same address
    /// in any list.
    ///
    /// - Returns: The text, or `nil` for no address.
    func text() -> String? {
        guard isKnown else { return nil }
        var raw = ipv4.map { SIMD2($0, 0) } ?? bytes
        let family = ipv4 == nil ? AF_INET6 : AF_INET
        return withUnsafeBytes(of: &raw) { address in
            withUnsafeTemporaryAllocation(of: CChar.self, capacity: Int(INET6_ADDRSTRLEN)) { text in
                guard let base = text.baseAddress,
                      inet_ntop(family, address.baseAddress, base, socklen_t(text.count)) != nil else { return nil }
                return String(cString: base)
            }
        }
    }
}
