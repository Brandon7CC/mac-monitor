//
//  FlowAddressScope.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/27/26.
//

import Foundation


// MARK: - An address's scope
/// Where a flow's remote address is in the address space, from IANA's IPv4 and IPv6 special-purpose address
/// registries. An IPv4 address no block holds is public. An IPv6 address is public only in 2000::/3, the space IANA
/// allocates for global unicast. A block the registries call reachable inside a reserved one, such as Teredo's
/// 2001::/32, is public. An IPv4-mapped address, or one in NAT64's well-known prefix 64:ff9b::/96, has the scope of
/// the IPv4 address in it.
public enum FlowAddressScope: String, Codable, CaseIterable, Sendable {
    /// Reachable across the internet.
    case `public`
    /// A private network's: RFC 1918, and IPv6 unique local addresses.
    case `private`
    /// The shared space carrier-grade NAT uses, which Tailscale uses too.
    case shared
    /// An address valid only on its own link: 169.254.0.0/16 and fe80::/10.
    case linkLocal = "link_local"
    case loopback
    case multicast
    /// Set aside and never routed across the internet: documentation, benchmarking, "this network", 240.0.0.0/4,
    /// protocol assignments, and IPv6 outside 2000::/3.
    case reserved

    /// A prefix and the scope of the addresses in it.
    struct Block {
        let bytes: [UInt8]
        let length: Int
        let scope: FlowAddressScope

        /// - Parameters:
        ///   - cidr: The prefix, as in `10.0.0.0/8`.
        ///   - scope: Its addresses' scope.
        init(_ cidr: String, _ scope: FlowAddressScope) {
            let parts = cidr.split(separator: "/")
            bytes = FlowAddressScope.bytes(of: String(parts[0])) ?? []
            length = Int(parts.last ?? "") ?? 0
            self.scope = scope
        }

        /// Does the block hold an address?
        ///
        /// - Parameter address: The address's bytes, of the block's family.
        /// - Returns: Whether its first `length` bits are the block's.
        func holds(_ address: [UInt8]) -> Bool {
            let whole = length / 8, bits = length % 8
            guard address.count == bytes.count, address.prefix(whole).elementsEqual(bytes.prefix(whole)) else {
                return false
            }
            return bits == 0 || (address[whole] ^ bytes[whole]) & ~(0xFF >> bits) == 0
        }
    }

    /// IPv4's blocks, the first that holds an address deciding its scope.
    static let ipv4 = [
        Block("0.0.0.0/8", .reserved), Block("10.0.0.0/8", .private), Block("100.64.0.0/10", .shared),
        Block("127.0.0.0/8", .loopback), Block("169.254.0.0/16", .linkLocal), Block("172.16.0.0/12", .private),
        Block("192.0.0.9/32", .public), Block("192.0.0.10/32", .public), Block("192.0.0.0/24", .reserved),
        Block("192.0.2.0/24", .reserved), Block("192.88.99.0/24", .reserved), Block("192.168.0.0/16", .private),
        Block("198.18.0.0/15", .reserved), Block("198.51.100.0/24", .reserved), Block("203.0.113.0/24", .reserved),
        Block("224.0.0.0/4", .multicast), Block("240.0.0.0/4", .reserved), Block("0.0.0.0/0", .public),
    ]

    /// IPv6's blocks, the first that holds an address deciding its scope.
    static let ipv6 = [
        Block("::1/128", .loopback), Block("2001::/32", .public), Block("2001:1::1/128", .public),
        Block("2001:1::2/128", .public), Block("2001:1::3/128", .public), Block("2001:3::/32", .public),
        Block("2001:4:112::/48", .public), Block("2001:20::/28", .public), Block("2001:30::/28", .public),
        Block("2001::/23", .reserved), Block("2001:db8::/32", .reserved), Block("3fff::/20", .reserved),
        Block("2000::/3", .public), Block("fc00::/7", .private), Block("fe80::/10", .linkLocal),
        Block("ff00::/8", .multicast), Block("::/0", .reserved),
    ]

    /// The IPv6 prefixes that carry an IPv4 address in their last 4 bytes: IPv4-mapped, and NAT64's well-known one.
    static let carryingIPv4 = [Block("::ffff:0:0/96", .public), Block("64:ff9b::/96", .public)]

    /// - Parameter address: An IPv4 or IPv6 address, as `inet_ntop` writes it.
    /// - Returns: `nil` when it isn't one.
    public init?(address: String) {
        guard var bytes = Self.bytes(of: address) else { return nil }
        if Self.carryingIPv4.contains(where: { $0.holds(bytes) }) { bytes = Array(bytes.suffix(4)) }
        let blocks = bytes.count == 4 ? Self.ipv4 : Self.ipv6
        self = blocks.first { $0.holds(bytes) }?.scope ?? .reserved
    }

    /// An address's bytes, in network order.
    ///
    /// - Parameter address: An IPv4 or IPv6 address.
    /// - Returns: Its 4 or 16 bytes, or `nil` when it isn't one.
    static func bytes(of address: String) -> [UInt8]? {
        var ipv4 = in_addr(), ipv6 = in6_addr()
        if inet_pton(AF_INET, address, &ipv4) == 1 { return withUnsafeBytes(of: &ipv4) { Array($0) } }
        if inet_pton(AF_INET6, address, &ipv6) == 1 { return withUnsafeBytes(of: &ipv6) { Array($0) } }
        return nil
    }
}
