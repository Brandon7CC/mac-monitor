//
//  NStatMessageBuilder.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Network statistics messages
/// Builds the kernel's network statistics messages byte by byte, for a chosen descriptor layout, so a test can play
/// a whole source's life to the client: its add, its updates with items, its removal, and errors.
struct NStatMessageBuilder {
    /// What a descriptor holds.
    struct Descriptor {
        var upid: UInt64 = 0, eupid: UInt64 = 0, start: UInt64 = 0, timestamp: UInt64 = 0
        var pid: Int32 = 0, epid: Int32 = 0
        var local: Endpoint?, remote: Endpoint?
        var name = ""
        var state: UInt32 = 0, ifnetProperties: UInt32 = 0
    }

    /// An address and port, as text.
    struct Endpoint {
        let address: String
        let port: UInt16
    }

    /// One item after an extended update's descriptor.
    enum Item {
        /// The domain item, with its name.
        case domain(String)
        /// The NECP parameters item: each parameter's type and text, or raw bytes.
        case parameters([(UInt8, [UInt8])])
        /// Any item, as its type and value.
        case raw(UInt32, [UInt8])
    }

    /// The TCP and UDP layouts messages are built for.
    var tcp = DescriptorLayout.tcp27, udp = DescriptorLayout.udp23

    /// - Parameter darwin: Build for Darwin 22, 23 or 27's layouts.
    init(darwin: Int = 27) {
        (tcp, udp) = darwin < 23 ? (.tcp22, .udp22) : darwin < 27 ? (.tcp23, .udp23) : (.tcp27, .udp23)
    }

    /// - Parameters:
    ///   - reference: The source reference.
    ///   - provider: Its provider.
    /// - Returns: `SRC_ADDED`.
    func added(_ reference: UInt64, _ provider: NStat.Provider) -> [UInt8] {
        message(.sourceAdded, length: 32) { $0.put(reference, at: 16); $0.put(provider.rawValue, at: 24) }
    }

    /// - Parameters:
    ///   - reference: The source reference.
    ///   - flags: Header flags, such as closed after a drop.
    /// - Returns: `SRC_REMOVED`.
    func removed(_ reference: UInt64, flags: UInt16 = 0) -> [UInt8] {
        message(.sourceRemoved, length: 24, flags: flags) { $0.put(reference, at: 16) }
    }

    /// - Parameters:
    ///   - request: The request it answers.
    ///   - errno: The error.
    ///   - echoing: Prepend it to the request's bytes, as the kernel does when it can.
    /// - Returns: `ERROR`.
    func error(_ request: NStat.Request, _ errno: Int32, echoing: [UInt8] = []) -> [UInt8] {
        message(.error, length: 24 + echoing.count, context: request.context) { body in
            body.put(UInt32(errno), at: 16)
            body.replaceSubrange(24..<body.count, with: echoing)
        }
    }

    /// - Parameters:
    ///   - reference: The source reference.
    ///   - provider: Its provider.
    ///   - descriptor: Its descriptor.
    ///   - received: The bytes it received.
    ///   - sent: The bytes it sent.
    ///   - flags: Header flags, such as closing.
    ///   - event: The event it was sent for.
    ///   - items: Items after the descriptor. With none, it's a plain update.
    /// - Returns: `SRC_UPDATE` or `SRC_EXTENDED_UPDATE`.
    func update(_ reference: UInt64, _ provider: NStat.Provider, _ descriptor: Descriptor, received: UInt64 = 0,
                sent: UInt64 = 0, flags: UInt16 = 0, event: UInt64 = 0, items: [Item] = [.domain("")]) -> [UInt8] {
        let layout = provider.kind == .tcp ? tcp : udp
        let tail = items.flatMap(Self.bytes(of:)), end = 152 + layout.size
        let type: NStat.MessageType = items.isEmpty ? .sourceUpdate : .sourceExtendedUpdate
        return message(type, length: end + tail.count, flags: flags) { body in
            body.put(reference, at: 16)
            body.put(event, at: 24)
            body.put(received, at: 40)
            body.put(sent, at: 56)
            body.put(provider.rawValue, at: 144)
            Self.write(descriptor, layout, into: &body, at: 152)
            body.replaceSubrange(end..<body.count, with: tail)
        }
    }

    /// - Parameters:
    ///   - reference: The source reference.
    ///   - provider: Its provider.
    ///   - descriptor: Its descriptor.
    /// - Returns: A legacy closing `SRC_DESC`.
    func description(_ reference: UInt64, _ provider: NStat.Provider, _ descriptor: Descriptor) -> [UInt8] {
        let layout = provider.kind == .tcp ? tcp : udp
        return message(.sourceDescription, length: 40 + layout.size, flags: NStat.closing) { body in
            body.put(reference, at: 16)
            body.put(provider.rawValue, at: 32)
            Self.write(descriptor, layout, into: &body, at: 40)
        }
    }

    /// - Parameters:
    ///   - reference: The source reference.
    ///   - received: The bytes it received.
    ///   - sent: The bytes it sent.
    /// - Returns: A legacy closing `SRC_COUNTS`.
    func counts(_ reference: UInt64, received: UInt64, sent: UInt64) -> [UInt8] {
        message(.sourceCounts, length: 144, flags: NStat.closing) { body in
            body.put(reference, at: 16)
            body.put(received, at: 40)
            body.put(sent, at: 56)
        }
    }

    /// A message: its header, then what `fill` writes.
    ///
    /// - Parameters:
    ///   - type: Its type.
    ///   - length: Its length before any items.
    ///   - context: Its context.
    ///   - flags: Its header flags.
    ///   - fill: Writes its fields.
    /// - Returns: The bytes.
    private func message(_ type: NStat.MessageType, length: Int, context: UInt64 = 0, flags: UInt16 = 0,
                         fill: (inout [UInt8]) -> Void) -> [UInt8] {
        var body = [UInt8](repeating: 0, count: length)
        body.put(context, at: 0)
        body.put(type.rawValue, at: 8)
        body.put(UInt16(length), at: 12)
        body.put(flags, at: 14)
        fill(&body)
        return body
    }

    /// Write a descriptor at its layout's offsets.
    ///
    /// - Parameters:
    ///   - descriptor: The descriptor.
    ///   - layout: Its layout.
    ///   - body: The message.
    ///   - base: Where the descriptor starts.
    private static func write(_ descriptor: Descriptor, _ layout: DescriptorLayout, into body: inout [UInt8],
                              at base: Int) {
        body.put(descriptor.upid, at: base + layout.upid)
        body.put(descriptor.eupid, at: base + layout.eupid)
        body.put(descriptor.start, at: base + layout.start)
        body.put(descriptor.timestamp, at: base + layout.timestamp)
        body.put(descriptor.pid, at: base + layout.pid)
        body.put(descriptor.epid, at: base + layout.epid)
        body.put(descriptor.ifnetProperties, at: base + layout.ifnetProperties)
        if let state = layout.state { body.put(descriptor.state, at: base + state) }
        for (endpoint, offset) in [(descriptor.local, layout.local), (descriptor.remote, layout.remote)] {
            if let endpoint { body.replaceSubrange((base + offset)..<(base + offset + 28), with: sockaddr(endpoint)) }
        }
        let name = Array(descriptor.name.utf8.prefix(63))
        body.replaceSubrange((base + layout.pname)..<(base + layout.pname + name.count), with: name)
    }

    /// A `sockaddr_in` or `sockaddr_in6` in 28 bytes.
    ///
    /// - Parameter endpoint: The address and port.
    /// - Returns: The bytes.
    static func sockaddr(_ endpoint: Endpoint) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 28)
        let isIPv6 = endpoint.address.contains(":")
        bytes[0] = isIPv6 ? 28 : 16
        bytes[1] = UInt8(isIPv6 ? AF_INET6 : AF_INET)
        bytes.put(endpoint.port.bigEndian, at: 2)
        bytes.withUnsafeMutableBytes { raw in
            _ = inet_pton(isIPv6 ? AF_INET6 : AF_INET, endpoint.address, raw.baseAddress! + (isIPv6 ? 8 : 4))
        }
        return bytes
    }

    /// An item's bytes: its header, then its value padded to 8 bytes.
    ///
    /// - Parameter item: The item.
    /// - Returns: The bytes.
    static func bytes(of item: Item) -> [UInt8] {
        let (type, value): (UInt32, [UInt8])
        switch item {
        case .domain(let name):
            var domain = [UInt8](repeating: 0, count: 1_056)
            domain.replaceSubrange(0..<min(name.utf8.count, 255), with: name.utf8.prefix(255))
            (type, value) = (1, domain)
        case .parameters(let parameters):
            (type, value) = (2, parameters.flatMap { tlv, bytes in
                var header = [UInt8](repeating: 0, count: 5)
                header[0] = tlv
                header.put(UInt32(bytes.count), at: 1)
                return header + bytes
            })
        case .raw(let rawType, let bytes):
            (type, value) = (rawType, bytes)
        }
        var header = [UInt8](repeating: 0, count: 8)
        header.put(type, at: 0)
        header.put(UInt32(value.count), at: 4)
        return header + value + [UInt8](repeating: 0, count: (8 - value.count % 8) % 8)
    }
}


extension Array where Element == UInt8 {
    /// Write an integer, little-endian, at an offset.
    ///
    /// - Parameters:
    ///   - value: The integer.
    ///   - offset: Where.
    mutating func put<T: FixedWidthInteger>(_ value: T, at offset: Int) {
        withUnsafeMutableBytes { $0.storeBytes(of: value.littleEndian, toByteOffset: offset, as: T.self) }
    }
}
