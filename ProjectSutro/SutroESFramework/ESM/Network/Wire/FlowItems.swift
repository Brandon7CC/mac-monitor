//
//  FlowItems.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - An update's items
/// What the kernel keeps of a flow's destination, from the items after an extended update's descriptor. That's its
/// host, the URL of its request, and the site that request was for.
///
/// Mac Monitor reads no DNS traffic for them. The domain item is the host the kernel keeps for the socket. A kernel
/// socket's is what its process set with `SO_NECP_ATTRIBUTES`, or else the name mDNSResponder last resolved its
/// remote address to for the same program, as for curl and Python. A userland flow its client marked as a tracker
/// carries the tracker's domain. The NECP parameters item is the process's own NECP client parameters, copied
/// unfiltered. TLV 3 is the host, TLV 42 (Darwin 25 and later) or 153 (Darwin 22) the URL, and TLV 34 the first-party
/// site.
struct FlowItems: Equatable {
    var hostname: String?
    /// The URL with its path, sanitized (``FlowURL``).
    var url: String?
    var firstPartySite: String?

    /// The domain item's type and length, the same on every Darwin so far, and the NECP parameters item's type.
    static let domainType: UInt32 = 1, domainLength: UInt32 = 1_056, parametersType: UInt32 = 2
    /// The NECP parameters the client reads.
    private static let hostTLV: UInt8 = 3, firstPartySiteTLV: UInt8 = 34, urlTLVs: Set<UInt8> = [42, 153]

    /// Is anything known?
    var isEmpty: Bool {
        hostname == nil && url == nil && firstPartySite == nil
    }

    /// Read the items after an update's descriptor.
    ///
    /// - Parameters:
    ///   - items: The items.
    ///   - provider: The source's provider. A TCP or QUIC flow's host is its TLV 3 when it has one, since the
    ///     domain item can be a tracker's. Any other's is the domain item's name.
    /// - Returns: What they hold.
    static func read(items: UnsafeRawBufferPointer, provider: NStat.Provider) -> FlowItems {
        var found = FlowItems(), domain: String?, host: String?
        forEachItem(in: items) { type, value in
            if type == domainType {
                let name = value.prefix(256)
                domain = text(UnsafeRawBufferPointer(rebasing: name[..<(name.firstIndex(of: 0) ?? name.endIndex)]))
                    .flatMap(dropDot)
            } else if type == parametersType, provider.carriesParameters {
                forEachParameter(in: value) { tlv, value in
                    switch tlv {
                    case hostTLV: host = host ?? text(value).flatMap(dropDot)
                    case firstPartySiteTLV: found.firstPartySite = found.firstPartySite ?? text(value)
                    case _ where urlTLVs.contains(tlv):
                        found.url = found.url ?? text(value).flatMap { FlowURL.sanitized($0, keepingPath: true) }
                    default: break
                    }
                }
            }
        }
        let preferHost = provider == .tcpUserland || provider == .quicUserland
        found.hostname = preferHost ? host ?? domain : domain
        return found
    }

    /// Walk the items. Each is a type and a length, both 4 bytes, then its value, padded to 8 bytes.
    ///
    /// - Parameters:
    ///   - items: The items.
    ///   - body: Called with each item's type and value.
    /// - Returns: Whether the items used up the bytes exactly. The walk stops at an item that runs past them.
    @discardableResult
    static func forEachItem(in items: UnsafeRawBufferPointer,
                            _ body: (UInt32, UnsafeRawBufferPointer) -> Void) -> Bool {
        var offset = 0
        while items.count - offset >= 8 {
            let type: UInt32 = items.integer(at: offset), length = Int(items.integer(at: offset + 4, as: UInt32.self))
            guard length <= items.count - offset - 8 else { return false }
            body(type, UnsafeRawBufferPointer(rebasing: items[(offset + 8)..<(offset + 8 + length)]))
            offset += 8 + ((length + 7) & ~7)
        }
        return offset == items.count
    }

    /// Walk NECP parameters. Each is a 1-byte type and a 4-byte length, then its value, with no padding. The walk
    /// stops when fewer than 5 bytes remain or a length runs past them, as the kernel's own walk does.
    ///
    /// - Parameters:
    ///   - parameters: The parameters.
    ///   - body: Called with each parameter's type and value.
    static func forEachParameter(in parameters: UnsafeRawBufferPointer,
                                 _ body: (UInt8, UnsafeRawBufferPointer) -> Void) {
        var offset = 0
        while parameters.count - offset >= 5 {
            let length = Int(parameters.integer(at: offset + 1, as: UInt32.self))
            guard length <= parameters.count - offset - 5 else { return }
            body(parameters[offset], UnsafeRawBufferPointer(rebasing: parameters[(offset + 5)..<(offset + 5 + length)]))
            offset += 5 + length
        }
    }

    /// A value as text.
    ///
    /// - Parameter bytes: The value.
    /// - Returns: The text without trailing NULs, or `nil` when that's empty or isn't UTF-8.
    private static func text(_ bytes: UnsafeRawBufferPointer) -> String? {
        var end = bytes.count
        while end > 0, bytes[end - 1] == 0 { end -= 1 }
        return end > 0 ? String(bytes: bytes[..<end], encoding: .utf8) : nil
    }

    /// - Parameter name: A DNS name.
    /// - Returns: The name without its trailing dot, or `nil` when nothing's left.
    private static func dropDot(_ name: String) -> String? {
        let trimmed = name.hasSuffix(".") ? String(name.dropLast()) : name
        return trimmed.isEmpty ? nil : trimmed
    }
}
