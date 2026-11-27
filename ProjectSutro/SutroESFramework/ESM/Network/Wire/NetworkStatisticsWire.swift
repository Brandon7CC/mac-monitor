//
//  NetworkStatisticsWire.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - The network statistics wire
/// The messages of the kernel's network statistics control socket, `com.apple.network.statistics`, as XNU's
/// `ntstat.h` lays them out. Every message starts with a 16-byte header, and every integer is little-endian.
enum NStat {
    /// A message's type.
    enum MessageType: UInt32 {
        case success = 0, error = 1
        case addAllSources = 1002, getUpdate = 1007
        case sourceAdded = 10001, sourceRemoved = 10002, sourceDescription = 10003, sourceCounts = 10004
        case sourceUpdate = 10006, sourceExtendedUpdate = 10007
    }

    /// Which kind of socket a source is. The client never asks for the connection provider (9). It has no addresses,
    /// and its URL and host are on the TCP and QUIC sources too.
    enum Provider: UInt32, CaseIterable {
        case tcpKernel = 2, tcpUserland = 3, udpKernel = 4, udpUserland = 5, quicUserland = 8, udpSubflow = 10

        /// The descriptor its updates carry. QUIC's is TCP's.
        var kind: DescriptorLayout.Kind {
            switch self {
            case .tcpKernel, .tcpUserland, .quicUserland: .tcp
            case .udpKernel, .udpUserland, .udpSubflow: .udp
            }
        }

        /// Does it carry a userland flow's NECP parameters, with its host and URL?
        var carriesParameters: Bool {
            self == .tcpUserland || self == .udpUserland || self == .quicUserland
        }

        /// What its add asks for. That's the domain item always, the NECP parameters where it carries them, and every
        /// interface but loopback. The kernel then holds back a loopback source's updates, and still sends its add
        /// and its removal. An unknown interface stays, for a socket that hasn't connected yet. A UDP subflow takes
        /// every interface, since which interface bits it reports isn't known.
        ///
        /// - Parameter darwin: This Mac's Darwin major version, which sets the interface bits.
        /// - Returns: The filter bits.
        func filter(darwin: Int) -> UInt64 {
            let items = carriesParameters ? NStat.domainItems | NStat.parameterItems : NStat.domainItems
            return self == .udpSubflow ? items : items | (NStat.interfaces(darwin: darwin) & ~NStat.loopbackInterfaces)
        }
    }

    /// Header flags that say more follows, the source is closing, it closed after a message to the client was
    /// dropped, or it closed after the filter held back its closing update.
    static let continuation: UInt16 = 0x2, closing: UInt16 = 0x4, closedAfterDrop: UInt16 = 0x8,
               closedAfterFilter: UInt16 = 0x10
    /// Filter bits that ask for the domain item and the NECP parameters item.
    static let domainItems: UInt64 = 1 << 41, parameterItems: UInt64 = 1 << 42
    /// The interface property of a source on loopback (`NSTAT_IFNET_IS_LOOPBACK`).
    static let loopbackInterface: UInt32 = 0x2
    /// The interface bits a loopback source can have. That's loopback, and the local or non-local bit the kernel
    /// adds to most sources.
    static let loopbackInterfaces = UInt64(loopbackInterface) | 0x800 | 0x1000
    /// The event a kernel TCP socket is asked to send an update for when it connects, from Darwin 23. It didn't come
    /// on macOS 27.2, so the client polls as well.
    static let flowStateOutbound: UInt64 = 0x2000

    /// The filter bits for interfaces. A filter that sets some gets a source's updates only when its interface has
    /// one of them. A filter that sets none gets every source's.
    ///
    /// - Parameter darwin: This Mac's Darwin major version. Darwin 22 and 23 have 17 bits, and Darwin 24 adds 2.
    /// - Returns: The bits.
    static func interfaces(darwin: Int) -> UInt64 {
        darwin >= 24 ? 0x7_FFFF : 0x1_FFFF
    }

    /// Which of the client's requests a reply answers, by the context the request carried. A source's query
    /// carries its source reference, which counts up from 1 and never reaches the others' top byte.
    enum Request: Equatable {
        /// The first query, which only puts the client in updates mode.
        case mode
        /// A provider's add.
        case add(Provider)
        /// A query for a source's update, at its add or a poll.
        case query(UInt64)
        /// A query that checks whether an open flow's removal was lost.
        case check(UInt64)

        /// The bits that tell the requests apart.
        private static let mask: UInt64 = 0xFF00_0000_0000_0000
        private static let modeBits: UInt64 = 0x7000_0000_0000_0000, addBits: UInt64 = 0x7100_0000_0000_0000,
                           checkBits: UInt64 = 0x7200_0000_0000_0000

        /// - Parameter context: A reply's context.
        init?(context: UInt64) {
            switch context & Self.mask {
            case 0: self = .query(context)
            case Self.modeBits: self = .mode
            case Self.checkBits: self = .check(context & ~Self.mask)
            case Self.addBits:
                guard let provider = Provider(rawValue: UInt32(truncatingIfNeeded: context)) else { return nil }
                self = .add(provider)
            default: return nil
            }
        }

        /// The context the request carries.
        var context: UInt64 {
            switch self {
            case .mode: Self.modeBits
            case .add(let provider): Self.addBits | UInt64(provider.rawValue)
            case .query(let reference): reference
            case .check(let reference): Self.checkBits | reference
            }
        }
    }

    /// Where a message's fields are.
    enum Offset {
        /// The source reference of every source message and of a query, and an error's errno.
        static let source = 16, error = 16
        /// The provider of an added source, and the event an update was sent for.
        static let addedProvider = 24, event = 24
        /// The bytes received and sent, in an update's or a counts message's counts.
        static let receivedBytes = 40, sentBytes = 56
        /// An update's provider and descriptor.
        static let updateProvider = 144, updateDescriptor = 152
        /// A legacy description's provider and descriptor.
        static let descriptionProvider = 32, descriptionDescriptor = 40
    }

    // MARK: Reading

    /// A message's header.
    struct Header {
        static let size = 16
        let context: UInt64, type: UInt32, length: UInt16, flags: UInt16

        /// - Parameter message: The message, at least 16 bytes.
        init(_ message: UnsafeRawBufferPointer) {
            context = message.integer(at: 0)
            type = message.integer(at: 8)
            length = message.integer(at: 12)
            flags = message.integer(at: 14)
        }

        /// - Parameter flag: A header flag.
        /// - Returns: Whether the header has it.
        func has(_ flag: UInt16) -> Bool {
            flags & flag != 0
        }
    }

    /// Walk the messages of one datagram by their headers' lengths. Darwin 25 and later pack several into one.
    ///
    /// - Parameters:
    ///   - datagram: The datagram.
    ///   - body: Called with each message's header and bytes, the header included.
    /// - Returns: `false` when the walk stopped early, at a length under 16 or past the datagram, or bytes left over.
    @discardableResult
    static func forEachMessage(in datagram: UnsafeRawBufferPointer,
                               _ body: (Header, UnsafeRawBufferPointer) -> Void) -> Bool {
        var offset = 0
        while datagram.count - offset >= Header.size {
            let header = Header(UnsafeRawBufferPointer(rebasing: datagram[offset...]))
            let end = offset + Int(header.length)
            guard Int(header.length) >= Header.size, end <= datagram.count else { return false }
            body(header, UnsafeRawBufferPointer(rebasing: datagram[offset..<end]))
            offset = end
        }
        return offset == datagram.count
    }

    // MARK: Requests

    /// Write the add for every source of a provider, 56 bytes, and hand it over.
    ///
    /// - Parameters:
    ///   - provider: The provider.
    ///   - filter: Its filter bits.
    ///   - events: The events to send updates for.
    ///   - context: The context its reply carries.
    ///   - send: Takes the request's bytes, valid only during the call.
    /// - Returns: What `send` returns.
    static func addAll<R>(_ provider: UInt32, filter: UInt64, events: UInt64, context: UInt64,
                          _ send: (UnsafeRawBufferPointer) -> R) -> R {
        request(.addAllSources, length: 56, context: context, flags: 0, send) { body in
            body.storeBytes(of: filter.littleEndian, toByteOffset: 16, as: UInt64.self)
            body.storeBytes(of: events.littleEndian, toByteOffset: 24, as: UInt64.self)
            body.storeBytes(of: provider.littleEndian, toByteOffset: 32, as: UInt32.self)
        }
    }

    /// Write a query for one source's update, 24 bytes, and hand it over.
    ///
    /// - Parameters:
    ///   - source: The source reference, or 0 for the query that only puts the client in updates mode.
    ///   - context: The context its reply carries.
    ///   - flags: Header flags. Never continuation for one source, which replaces a pending poll of every source.
    ///   - send: Takes the request's bytes, valid only during the call.
    /// - Returns: What `send` returns.
    static func getUpdate<R>(_ source: UInt64, context: UInt64, flags: UInt16 = 0,
                             _ send: (UnsafeRawBufferPointer) -> R) -> R {
        request(.getUpdate, length: 24, context: context, flags: flags, send) { body in
            body.storeBytes(of: source.littleEndian, toByteOffset: Offset.source, as: UInt64.self)
        }
    }

    /// Write a request in a zeroed stack buffer and hand it over.
    ///
    /// - Parameters:
    ///   - type: The request's type.
    ///   - length: Its length.
    ///   - context: Its context.
    ///   - flags: Its header flags.
    ///   - send: Takes the bytes.
    ///   - fill: Writes the fields after the header.
    /// - Returns: What `send` returns.
    private static func request<R>(_ type: MessageType, length: Int, context: UInt64, flags: UInt16,
                                   _ send: (UnsafeRawBufferPointer) -> R,
                                   fill: (UnsafeMutableRawBufferPointer) -> Void) -> R {
        withUnsafeTemporaryAllocation(byteCount: length, alignment: 8) { body in
            body.initializeMemory(as: UInt8.self, repeating: 0)
            body.storeBytes(of: context.littleEndian, toByteOffset: 0, as: UInt64.self)
            body.storeBytes(of: type.rawValue.littleEndian, toByteOffset: 8, as: UInt32.self)
            body.storeBytes(of: UInt16(length).littleEndian, toByteOffset: 12, as: UInt16.self)
            body.storeBytes(of: flags.littleEndian, toByteOffset: 14, as: UInt16.self)
            fill(body)
            return send(UnsafeRawBufferPointer(body))
        }
    }

    // MARK: The system

    /// This Mac's Darwin major version, from `uname`. It's 22 on macOS 13 and 23 on macOS 14.
    static let darwinMajor: Int = {
        var name = utsname()
        guard uname(&name) == 0 else { return 0 }
        let release = withUnsafeBytes(of: &name.release) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
        return Int(release.prefix { $0 != "." }) ?? 0
    }()

    /// How many times the kernel couldn't queue a source's add for any client since it started
    /// (`net.stats.stats`, its seventh counter).
    ///
    /// - Returns: The count, or `nil` when it can't be read.
    static func addFailures() -> UInt32? {
        var stats = [UInt32](repeating: 0, count: 16)
        var size = stats.count * MemoryLayout<UInt32>.size
        guard sysctlbyname("net.stats.stats", &stats, &size, nil, 0) == 0, size >= 7 * 4 else { return nil }
        return stats[6]
    }
}


extension UnsafeRawBufferPointer {
    /// A little-endian integer at an offset.
    ///
    /// - Parameters:
    ///   - offset: Its offset.
    ///   - type: Its type.
    /// - Returns: The integer, or 0 when it runs past the end.
    func integer<T: FixedWidthInteger>(at offset: Int, as type: T.Type = T.self) -> T {
        guard offset >= 0, offset + MemoryLayout<T>.size <= count else { return 0 }
        return T(littleEndian: loadUnaligned(fromByteOffset: offset, as: T.self))
    }
}
