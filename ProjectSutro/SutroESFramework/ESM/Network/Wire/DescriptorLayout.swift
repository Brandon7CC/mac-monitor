//
//  DescriptorLayout.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Descriptor layouts
/// Where a source descriptor's fields are. The kernel's TCP and UDP descriptors grew twice, on Darwin 23 (macOS 14
/// to 26 share one layout) and on Darwin 27. A layout is picked by size, not by version.
struct DescriptorLayout: Equatable {
    /// Which descriptor. QUIC sources carry TCP's.
    enum Kind: CaseIterable {
        case tcp, udp
    }

    let kind: Kind
    /// The descriptor's size in bytes.
    let size: Int
    /// The offsets of its fields.
    let upid, eupid, start, timestamp, pid, epid, local, remote, pname, ifnetProperties: Int
    /// The offset of a TCP descriptor's state. UDP has none.
    let state: Int?

    static let tcp22 = tcp(size: 336, ifnetProperties: 328)
    static let tcp23 = tcp(size: 344, ifnetProperties: 336)
    static let tcp27 = tcp(size: 360, ifnetProperties: 352)
    static let udp22 = udp(size: 272, ifnetProperties: 264)
    static let udp23 = udp(size: 280, ifnetProperties: 272)

    /// A TCP layout. The fields before the interface properties never moved.
    ///
    /// - Parameters:
    ///   - size: Its size.
    ///   - ifnetProperties: Where its interface properties are.
    /// - Returns: The layout.
    private static func tcp(size: Int, ifnetProperties: Int) -> DescriptorLayout {
        DescriptorLayout(kind: .tcp, size: size, upid: 0, eupid: 8, start: 16, timestamp: 24, pid: 116, epid: 120,
                         local: 124, remote: 152, pname: 196, ifnetProperties: ifnetProperties, state: 76)
    }

    /// A UDP layout. The fields before the interface properties never moved.
    ///
    /// - Parameters:
    ///   - size: Its size.
    ///   - ifnetProperties: Where its interface properties are.
    /// - Returns: The layout.
    private static func udp(size: Int, ifnetProperties: Int) -> DescriptorLayout {
        DescriptorLayout(kind: .udp, size: size, upid: 0, eupid: 8, start: 16, timestamp: 24, pid: 128, epid: 196,
                         local: 56, remote: 84, pname: 132, ifnetProperties: ifnetProperties, state: nil)
    }

    /// The layouts known of a kind, largest first.
    ///
    /// - Parameter kind: The kind.
    /// - Returns: The layouts.
    static func known(_ kind: Kind) -> [DescriptorLayout] {
        kind == .tcp ? [tcp27, tcp23, tcp22] : [udp23, udp22]
    }

    /// The layout a message's descriptor has. It's the first known one that fits, largest first, else the one the
    /// running NetworkStatistics framework was built with, if that fits.
    ///
    /// - Parameters:
    ///   - kind: The message's kind of descriptor.
    ///   - message: A whole update or description message.
    ///   - offset: Where its descriptor starts.
    ///   - fallback: The layout to try when none known fits.
    /// - Returns: The layout, or `nil` when none fits.
    static func detect(_ kind: Kind, _ message: UnsafeRawBufferPointer, at offset: Int,
                       fallback: (Kind) -> DescriptorLayout? = DescriptorEncoding.layout(of:)) -> DescriptorLayout? {
        known(kind).first { $0.fits(message, at: offset) }
            ?? fallback(kind).flatMap { $0.fits(message, at: offset) ? $0 : nil }
    }

    /// Does the layout fit a message? A plain one ends with the descriptor. An extended update must have the domain
    /// item right after it, whose items then use the message up exactly. The kernel zeroes a message, so a layout 8
    /// bytes short of the real one would read the last 8 bytes as an empty item and use the message up as well.
    /// The domain item rules that out. Every source carries it, since the client asks for it, and its length is
    /// never 0. It may grow on a later macOS, so only its least length is required.
    ///
    /// - Parameters:
    ///   - message: A whole update or description message.
    ///   - offset: Where its descriptor starts.
    /// - Returns: Whether it fits, and the descriptor looks like one.
    func fits(_ message: UnsafeRawBufferPointer, at offset: Int) -> Bool {
        let end = offset + size
        guard message.count >= end else { return false }
        if NStat.Header(message).type == NStat.MessageType.sourceExtendedUpdate.rawValue {
            let items = UnsafeRawBufferPointer(rebasing: message[end...])
            guard items.integer(at: 0, as: UInt32.self) == FlowItems.domainType,
                  items.integer(at: 4, as: UInt32.self) >= FlowItems.domainLength,
                  FlowItems.forEachItem(in: items, { _, _ in }) else { return false }
        } else if message.count != end {
            return false
        }
        return FlowDescriptor(message, at: offset, layout: self)?.isPlausible == true
    }
}
